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
	return InstallBaseline(l, run, binary, "")
}

// InstallBaseline is Install with baseline (a file, "" for none) put down
// as the install's baseline: at l.Baseline, immutable, in the manifest and
// backed up, and passed to the agent by its unit. An install without one
// keeps the baseline an earlier install put down.
func InstallBaseline(l Layout, run Runner, binary, baseline string) (Report, error) {
	var rep Report
	bin, err := os.ReadFile(binary)
	if err != nil {
		return rep, err
	}
	if _, err := os.Stat(l.p(l.Config)); err != nil {
		return rep, fmt.Errorf("no config to install: %w", err)
	}
	var base []byte
	if baseline != "" {
		if l.Baseline == "" {
			return rep, errors.New("this layout has no place for a baseline")
		}
		if base, err = os.ReadFile(baseline); err != nil {
			return rep, fmt.Errorf("baseline: %w", err)
		}
	}
	items, err := collectBase(l, bin, base)
	if err != nil {
		return rep, err
	}
	// Stage: every changed file under a temporary name.
	var todo []item
	m := manifestOf(items, sum(bin))
	for _, it := range items {
		if cur, err := os.ReadFile(l.p(it.path)); err == nil && bytes.Equal(cur, it.content) {
			continue
		}
		todo = append(todo, it)
	}
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
	// The install is back: ensure and the guards keep it again.
	if l.Uninstalled != "" {
		if err := os.Remove(l.p(l.Uninstalled)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return rep, err
		}
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

// collect is every file an install puts down besides the pinned hash and
// the manifest. bin is the binary; nil leaves the copies' content empty.
// The baseline is the one on the box, if there is one.
func collect(l Layout, bin []byte) ([]item, error) { return collectBase(l, bin, nil) }

// collectBase is collect with base as the install's baseline; nil keeps
// the one on the box (or its backup), if there is one.
func collectBase(l Layout, bin, base []byte) ([]item, error) {
	if base == nil && l.Baseline != "" {
		for _, p := range []string{l.Baseline, l.baseBackup()} {
			if b, err := os.ReadFile(l.p(p)); err == nil {
				base = b
				break
			} else if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
		}
	}
	var items []item
	for _, c := range l.Copies {
		items = append(items, item{path: c, content: bin, mode: 0o755, kind: "copy"})
	}
	for _, f := range render(l, base != nil) {
		items = append(items, item{path: f.Path, content: f.Content, mode: f.Mode, kind: "file"})
	}
	if base != nil {
		items = append(items, item{path: l.Baseline, content: base, mode: 0o600, kind: "config", source: l.baseBackup()},
			item{path: l.baseBackup(), content: base, mode: 0o600, kind: "backup", source: l.Baseline})
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
		return nil, err
	}
	if err := pair(l.Config + ".sig"); err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(l.p(l.FleetDir))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := pair(l.FleetDir + "/" + e.Name()); err != nil {
				return nil, err
			}
		}
	}
	return items, nil
}

// manifestOf is the manifest of items, sorted by path; the copies get
// copyHash.
func manifestOf(items []item, copyHash string) Manifest {
	var m Manifest
	for _, it := range items {
		h := sum(it.content)
		if it.kind == "copy" {
			h = copyHash
		}
		m.Entries = append(m.Entries, Entry{Path: it.path, SHA256: h, Mode: uint32(it.mode), Kind: it.kind, Source: it.source})
	}
	slices.SortFunc(m.Entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return m
}

// Uninstall writes the uninstalled marker, removes the pinned hash (so nothing can be restored or launched
// while it works), stops the guards and the timer, makes everything of the manifest
// mutable again, removes it and the manifest, deletes the firewall table,
// reloads systemd and last stops the agent's unit: the agent may be the
// caller, and stopping it ends the process. Every step runs whatever the
// others did; nothing installed is a success.
func Uninstall(l Layout, run Runner) error { return UninstallThen(l, run, nil) }

// UninstallThen is Uninstall with last run just before the agent's unit is
// stopped, once all else worked: what the agent must do while it still
// can (it may be the caller, and the stop ends it).
func UninstallThen(l Layout, run Runner, last func()) error {
	// The pinned hash first: from here no launch point finds a good copy
	// and ensure restores and starts nothing, so a guard caught mid-look
	// by the stop below cannot bring anything back.
	var errs []string
	// The marker before all: it is what says "uninstalled" to ensure, the
	// guards and the agent, whatever files remain.
	if l.Uninstalled != "" {
		if err := atomic(l.p(l.Uninstalled), nil, 0o600); err != nil {
			return fmt.Errorf("uninstalled marker: %w", err)
		}
	}
	for _, p := range []string{l.Pinned, l.Backup + "/pinned.sha256"} {
		full := l.p(p)
		if _, err := os.Lstat(full); err != nil {
			continue
		}
		run("chattr", "-i", full)
		if err := os.Remove(full); err != nil {
			errs = append(errs, err.Error())
		}
	}
	var others []string
	for _, u := range Units {
		if u != agentUnit {
			others = append(others, u)
		}
	}
	_, gerr := run("systemctl", append([]string{"disable", "--now"}, others...)...)
	// Without --now: the wants link goes while the agent keeps running; once
	// the unit file is gone systemd could no longer disable it.
	_, aerr := run("systemctl", "disable", agentUnit)
	m, err := ReadManifest(l)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	paths := []string{l.Manifest, l.Pinned, l.Backup + "/manifest.json", l.Backup + "/pinned.sha256"}
	for _, e := range m.Entries {
		paths = append(paths, e.Path)
	}
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
	// A unit that was never there is not a failure: only report when there was an install.
	if len(m.Entries) > 0 {
		for _, e := range []error{gerr, aerr} {
			if e != nil {
				errs = append(errs, "systemctl disable: "+e.Error())
			}
		}
	}
	if errs != nil {
		return errors.New(strings.Join(errs, "; "))
	}
	// Last, and only when all else worked: a loaded unit can be stopped after
	// its file is gone, and stopping it ends the agent if it is the caller. A
	// failed removal leaves the agent running so the token can be used again.
	// A guard restarted by a start queued as it stopped failed on the
	// missing copy: cleared, so no unit is left behind.
	run("systemctl", append([]string{"reset-failed"}, Units...)...)
	if last != nil {
		last()
	}
	run("systemctl", "stop", agentUnit)
	return nil
}

const agentUnit = "xdr-agent.service"

// Repin rewrites what is missing of the pinned hash (both copies, from
// hash) and of the manifest (both copies, from manifest when given, else
// rebuilt as install would write it), makes them immutable and returns what
// it wrote. Nothing on a box marked uninstalled.
func Repin(l Layout, run Runner, hash string, manifest []byte) ([]string, error) {
	if Uninstalled(l) || hash == "" {
		return nil, nil
	}
	var wrote, errs []string
	missing := func(p string) bool { _, err := os.Lstat(l.p(p)); return errors.Is(err, fs.ErrNotExist) }
	if manifest == nil && missing(l.Manifest) && missing(l.Backup+"/manifest.json") {
		items, err := collect(l, nil)
		if err != nil {
			return nil, err
		}
		manifest, _ = json.Marshal(manifestOf(items, hash))
	}
	pinned := []byte(hash + "\n")
	for _, f := range []item{
		{path: l.Pinned, content: pinned, mode: 0o644},
		{path: l.Backup + "/pinned.sha256", content: pinned, mode: 0o600},
		{path: l.Manifest, content: manifest, mode: 0o644},
		{path: l.Backup + "/manifest.json", content: manifest, mode: 0o600},
	} {
		if f.content == nil || !missing(f.path) {
			continue
		}
		if err := atomic(l.p(f.path), f.content, f.mode); err != nil {
			errs = append(errs, f.path+": "+err.Error())
			continue
		}
		run("chattr", "+i", l.p(f.path))
		wrote = append(wrote, f.path)
	}
	if errs != nil {
		return wrote, errors.New(strings.Join(errs, "; "))
	}
	return wrote, nil
}
