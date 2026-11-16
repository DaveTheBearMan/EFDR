package sshgate

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/config"
	"xdr/internal/pathenc"
)

const (
	sshdConfig = "/etc/ssh/sshd_config"
	sshdDropIn = "/etc/ssh/sshd_config.d"
	pamSSHD    = "/etc/pam.d/sshd"
)

// ErrNoBase is Assert's error when the baseline lacks a file the render
// starts from: the gate stays off.
var ErrNoBase = errors.New("gate off: the baseline has no copy of")

// Asserter keeps sshd's and PAM's config at their render.
type Asserter struct {
	Root   string // "/" on a box
	State  string // the agent's state directory
	Run    Runner
	Output func(name string, args ...string) ([]byte, error)
}

// write is one file Assert changed and what to put back.
type write struct {
	path string // absolute, under Root
	prev []byte // nil: it did not exist
	mode fs.FileMode
	to   string // a quarantined file's new place; "" for a rewrite
}

// Assert writes sshd_config and pam.d/sshd where they differ from the
// render, puts baseline drop-ins back to their baseline content and moves
// the others to State/quarantine. When anything changed, sshd -t must
// accept the result, else all of it is put back and the error names
// sshd -t; when it does, ssh is reloaded. changed is the box paths.
func (a *Asserter) Assert(cfg *config.Config, base *baseline.Baseline, gateExe string) (changed []string, err error) {
	sshdBase, ok1 := baseContent(base, sshdConfig)
	pamBase, ok2 := baseContent(base, pamSSHD)
	for p, ok := range map[string]bool{sshdConfig: ok1, pamSSHD: ok2} {
		if !ok {
			return nil, fmt.Errorf("%w %s", ErrNoBase, p)
		}
	}
	pam, err := RenderPAM(pamBase, cfg, gateExe)
	if err != nil {
		return nil, err
	}
	t0, err := a.T0(cfg)
	if err != nil {
		return nil, err
	}
	want := map[string][]byte{sshdConfig: RenderSSHD(sshdBase, cfg, t0), pamSSHD: pam}
	ents, err := os.ReadDir(a.path(sshdDropIn))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	var quarantine []string
	for _, e := range ents {
		p := sshdDropIn + "/" + e.Name()
		if c, ok := baseContent(base, p); ok && e.Type().IsRegular() {
			want[p] = c
		} else {
			quarantine = append(quarantine, p)
		}
	}
	var done []write
	undo := func() {
		for _, w := range slices.Backward(done) {
			switch {
			case w.to != "":
				moveFile(w.to, w.path)
			case w.prev == nil:
				os.Remove(w.path)
			default:
				writeFile(w.path, w.prev, w.mode)
			}
		}
	}
	paths := make([]string, 0, len(want))
	for p := range want {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, p := range paths {
		full := a.path(p)
		prev, err := collect.ReadFile(full, 1<<20)
		if err == nil && bytes.Equal(prev, want[p]) {
			continue
		}
		mode := fs.FileMode(0o644)
		if st, err := os.Lstat(full); err == nil && st.Mode().IsRegular() {
			mode = st.Mode().Perm()
		}
		if err != nil {
			prev = nil
		}
		if err := writeFile(full, want[p], 0o644); err != nil {
			undo()
			return nil, err
		}
		done = append(done, write{path: full, prev: prev, mode: mode})
		changed = append(changed, p)
	}
	if len(quarantine) > 0 {
		q := filepath.Join(a.State, "quarantine")
		if err := os.MkdirAll(q, 0o700); err != nil {
			undo()
			return nil, err
		}
		for _, p := range quarantine {
			to := filepath.Join(q, strconv.FormatInt(time.Now().UnixNano(), 10)+"-"+filepath.Base(p))
			if err := moveFile(a.path(p), to); err != nil {
				undo()
				return nil, err
			}
			done = append(done, write{path: a.path(p), to: to})
			changed = append(changed, p)
		}
	}
	if len(changed) == 0 {
		return nil, nil
	}
	if out, err := a.Output("sshd", "-t", "-f", a.path(sshdConfig)); err != nil {
		undo()
		return nil, fmt.Errorf("sshd -t refused the render, put back: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := a.Run("systemctl", "try-reload-or-restart", "ssh.service"); err != nil {
		return changed, fmt.Errorf("reloading ssh: %w", err)
	}
	return changed, nil
}

func (a *Asserter) path(p string) string { return filepath.Join(a.Root, p) }

func baseContent(b *baseline.Baseline, p string) ([]byte, bool) {
	e, ok := b.Files[pathenc.Encode(p)]
	if !ok || e.Content == nil && e.Size > 0 {
		return nil, false
	}
	return e.Content, true
}

// writeFile replaces path by a temp file and a rename.
func writeFile(path string, data []byte, mode fs.FileMode) error {
	tmp := path + ".xdr-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// moveFile renames, or copies and removes when from and to are on
// different filesystems.
func moveFile(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	st, err := os.Lstat(from)
	if err != nil {
		return err
	}
	data, err := collect.ReadFile(from, 1<<20)
	if err != nil {
		return err
	}
	if err := writeFile(to, data, st.Mode().Perm()); err != nil {
		return err
	}
	return os.Remove(from)
}

// T0 is the gray accounts' settings at T-0: read once from sshd -T for the
// first gray account and kept in State/sshd-t0.json, so later renders do
// not read back their own. With no gray accounts it is the zero T0.
func (a *Asserter) T0(cfg *config.Config) (T0, error) {
	var t T0
	if len(cfg.GrayUsers) == 0 {
		return t, nil
	}
	path := filepath.Join(a.State, "sshd-t0.json")
	if data, err := collect.ReadFile(path, 4096); err == nil {
		if err := json.Unmarshal(data, &t); err == nil {
			return t, nil
		}
	}
	addr := cfg.Jump[0].Addr()
	if len(cfg.SSHFrom) > 0 {
		addr = cfg.SSHFrom[0].Addr()
	}
	out, err := a.Output("sshd", "-T", "-C", fmt.Sprintf("user=%s,host=x,addr=%s", cfg.GrayUsers[0], addr))
	if err != nil {
		return t, fmt.Errorf("sshd -T: %w", err)
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		switch k {
		case "passwordauthentication":
			t.Password = v
		case "kbdinteractiveauthentication":
			t.KbdInteractive = v
		case "pubkeyauthentication":
			t.Pubkey = v
		case "authenticationmethods":
			t.Methods = v
		}
	}
	if t.Password == "" {
		return t, fmt.Errorf("sshd -T: no passwordauthentication in its output")
	}
	if err := os.MkdirAll(a.State, 0o700); err != nil {
		return t, err
	}
	data, _ := json.Marshal(t)
	return t, writeFile(path, data, 0o600)
}
