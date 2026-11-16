package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// item is a file to be put down.
type item struct {
	path    string // as the box sees it
	content []byte
	mode    fs.FileMode
	kind    string
	source  string
}

// Install puts the binary (three copies, its hash pinned), a backup of the
// config and the fleet bundle, the launch points and a manifest on the
// box, makes them immutable, and starts the units. Running it again with
// nothing changed changes nothing. Every file is written to a temporary
// name first and only renamed once all of them were, so a failure leaves
// the previous install as it was.
func Install(l Layout, run Runner, binary string) (Report, error) {
	var rep Report
	bin, err := os.ReadFile(binary)
	if err != nil {
		return rep, err
	}
	if _, err := os.Stat(l.p(l.Config)); err != nil {
		return rep, fmt.Errorf("no config to install: %w", err)
	}
	var items []item
	for _, c := range l.Copies {
		items = append(items, item{path: c, content: bin, mode: 0o755, kind: "copy"})
	}
	for _, f := range Render(l) {
		items = append(items, item{path: f.Path, content: f.Content, mode: f.Mode, kind: "file"})
	}
	// The config, its signature and the bundle, each with a backup beside
	// the manifest: ensure restores either from the other.
	pair := func(orig string) error {
		b, err := os.ReadFile(l.p(orig))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		st, err := os.Stat(l.p(orig))
		if err != nil {
			return err
		}
		backup := l.Backup + "/" + strings.TrimPrefix(orig, filepath.Dir(l.Config)+"/")
		items = append(items, item{path: orig, content: b, mode: st.Mode().Perm(), kind: "config", source: backup},
			item{path: backup, content: b, mode: 0o600, kind: "backup", source: orig})
		return nil
	}
	if err := pair(l.Config); err != nil {
		return rep, err
	}
	if err := pair(l.Config + ".sig"); err != nil {
		return rep, err
	}
	ents, err := os.ReadDir(l.p(l.FleetDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return rep, err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := pair(l.FleetDir + "/" + e.Name()); err != nil {
				return rep, err
			}
		}
	}

	// Stage: every changed file under a temporary name.
	var todo []item
	var m Manifest
	for _, it := range items {
		m.Entries = append(m.Entries, Entry{Path: it.path, SHA256: sum(it.content), Mode: uint32(it.mode), Kind: it.kind, Source: it.source})
		if cur, err := os.ReadFile(l.p(it.path)); err == nil && bytes.Equal(cur, it.content) {
			continue
		}
		todo = append(todo, it)
	}
	slices.SortFunc(m.Entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	var tmps []string
	cleanup := func() {
		for _, t := range tmps {
			os.Remove(t)
		}
	}
	for _, it := range todo {
		full := l.p(it.path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			cleanup()
			return rep, fmt.Errorf("%s: %w", it.path, err)
		}
		tmp := full + ".xdr-new"
		if err := os.WriteFile(tmp, it.content, it.mode); err != nil {
			cleanup()
			return rep, fmt.Errorf("%s: %w", it.path, err)
		}
		tmps = append(tmps, tmp)
		os.Chmod(tmp, it.mode)
	}
	// Commit.
	for _, it := range todo {
		full := l.p(it.path)
		run("chattr", "-i", full) // a file of an earlier install
		if err := os.Rename(full+".xdr-new", full); err != nil {
			cleanup()
			return rep, fmt.Errorf("%s: %w", it.path, err)
		}
		rep.Wrote = append(rep.Wrote, it.path)
	}
	manifest, _ := json.Marshal(m)
	pinned := []byte(sum(bin) + "\n")
	for _, f := range []item{
		{path: l.Pinned, content: pinned, mode: 0o644},
		{path: l.Backup + "/pinned.sha256", content: pinned, mode: 0o600},
		{path: l.Manifest, content: manifest, mode: 0o644},
		{path: l.Backup + "/manifest.json", content: manifest, mode: 0o600},
	} {
		full := l.p(f.path)
		if cur, err := os.ReadFile(full); err == nil && bytes.Equal(cur, f.content) {
			continue
		}
		run("chattr", "-i", full)
		if err := atomic(full, f.content, f.mode); err != nil {
			return rep, fmt.Errorf("%s: %w", f.path, err)
		}
		rep.Wrote = append(rep.Wrote, f.path)
	}
	if len(rep.Wrote) == 0 {
		return rep, nil
	}
	for _, e := range m.Entries {
		run("chattr", "+i", l.p(e.Path))
	}
	for _, p := range []string{l.Pinned, l.Manifest, l.Backup + "/pinned.sha256", l.Backup + "/manifest.json"} {
		run("chattr", "+i", l.p(p))
	}
	run("systemctl", "daemon-reload")
	if out, err := run("systemctl", append([]string{"enable", "--now"}, Units...)...); err != nil {
		return rep, fmt.Errorf("systemctl enable --now: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return rep, nil
}

// Uninstall stops the units, makes everything of the manifest mutable again,
// removes it and the manifest, and deletes the firewall table. Nothing
// installed is a success.
func Uninstall(l Layout, run Runner) error {
	run("systemctl", append([]string{"disable", "--now"}, Units...)...)
	m, err := ReadManifest(l)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	paths := []string{l.Manifest, l.Pinned, l.Backup + "/manifest.json", l.Backup + "/pinned.sha256"}
	for _, e := range m.Entries {
		paths = append(paths, e.Path)
	}
	var errs []string
	for _, p := range paths {
		full := l.p(p)
		if _, err := os.Lstat(full); err != nil {
			continue
		}
		run("chattr", "-i", full)
		if err := os.Remove(full); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for _, d := range []string{l.Backup, "/usr/lib/xdr", "/var/lib/xdr/bin"} {
		os.RemoveAll(l.p(d))
	}
	run("nft", "delete", "table", "inet", "xdr")
	run("systemctl", "daemon-reload")
	if errs != nil {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
