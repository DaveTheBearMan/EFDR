package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Ensure puts back whatever of the manifest is missing or differs, from a
// copy of the binary that matches the pinned hash (binary copies), from the
// backup (the config, its signature and the bundle, and the backup from
// them) or from Render (units and hooks), makes the files immutable again,
// and starts the units that are not running. With no good copy it trusts
// nothing: it restores nothing and says so.
func Ensure(l Layout, run Runner) (Report, error) {
	var rep Report
	pinned, err := pinnedHash(l)
	if err != nil {
		return rep, fmt.Errorf("not installed (%w)", err)
	}
	var good []byte
	for _, c := range l.Copies {
		if b, err := os.ReadFile(l.p(c)); err == nil && sum(b) == pinned {
			good = b
			break
		}
	}
	if good == nil {
		return rep, fmt.Errorf("no copy of the binary matches the pinned hash %s (copies: %s)", pinned[:min(12, len(pinned))], strings.Join(l.Copies, ", "))
	}
	m, err := ReadManifest(l)
	if err != nil {
		return rep, fmt.Errorf("manifest: %w", err)
	}
	rendered := map[string]File{}
	for _, f := range Render(l) {
		rendered[f.Path] = f
	}
	put := func(path string, content []byte, mode fs.FileMode) error {
		full := l.p(path)
		run("chattr", "-i", full)
		if err := atomic(full, content, mode); err != nil {
			return err
		}
		run("chattr", "+i", full)
		return nil
	}
	// The pinned hash and the manifest first: they are what the rest rests on.
	for _, f := range []struct{ path, backup string }{{l.Pinned, l.Backup + "/pinned.sha256"}, {l.Manifest, l.Backup + "/manifest.json"}} {
		if _, err := os.Stat(l.p(f.path)); err == nil {
			continue
		}
		if b, err := os.ReadFile(l.p(f.backup)); err == nil {
			if err := put(f.path, b, 0o644); err == nil {
				rep.Restored = append(rep.Restored, f.path)
			}
		}
	}
	var errs []string
	unitChanged := false
	for _, e := range m.Entries {
		if b, err := os.ReadFile(l.p(e.Path)); err == nil && sum(b) == e.SHA256 {
			continue
		}
		var content []byte
		switch e.Kind {
		case "copy":
			content = good
		case "file":
			if f, ok := rendered[e.Path]; ok && sum(f.Content) == e.SHA256 {
				content = f.Content
			}
		case "config", "backup":
			if b, err := os.ReadFile(l.p(e.Source)); err == nil && sum(b) == e.SHA256 {
				content = b
			}
		}
		if content == nil {
			errs = append(errs, e.Path+": no good source to restore it from")
			continue
		}
		if err := put(e.Path, content, fs.FileMode(e.Mode)); err != nil {
			errs = append(errs, e.Path+": "+err.Error())
			continue
		}
		rep.Restored = append(rep.Restored, e.Path)
		unitChanged = unitChanged || strings.HasPrefix(e.Path, "/etc/systemd/system/")
	}
	if unitChanged {
		run("systemctl", "daemon-reload")
	}
	for _, u := range Units {
		if out, _ := run("systemctl", "is-active", u); strings.TrimSpace(string(out)) == "active" {
			continue
		}
		if _, err := run("systemctl", "start", u); err != nil {
			errs = append(errs, "starting "+u+": "+err.Error())
			continue
		}
		rep.Started = append(rep.Started, u)
	}
	if errs != nil {
		return rep, errors.New(strings.Join(errs, "; "))
	}
	return rep, nil
}
