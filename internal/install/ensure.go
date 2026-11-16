package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrNotInstalled is Ensure's error on a box marked uninstalled, or with
// neither a pinned hash nor any of the install's units (never installed).
var ErrNotInstalled = errors.New("not installed")

// Ensure puts back whatever of the manifest is missing or differs, from a
// copy of the binary that matches the pinned hash (binary copies), from the
// backup (the config, its signature and the bundle, and the backup from
// them) or from Render (units and hooks), makes the files immutable again,
// and starts the units that are not running. With no good copy it trusts
// nothing: it restores nothing and says so.
// What it did, or why it could not, is left as a note (see TakeNotes).
func Ensure(l Layout, run Runner) (Report, error) {
	if Uninstalled(l) {
		return Report{}, fmt.Errorf("%w (marked uninstalled)", ErrNotInstalled)
	}
	pinned, err := pinnedHash(l)
	if err != nil && !UnitsPresent(l) {
		return Report{}, fmt.Errorf("%w (%w)", ErrNotInstalled, err)
	}
	var rep Report
	if err != nil {
		// Both pinned copies gone while the units are there: nothing to
		// trust a copy by. The agent rewrites them; this is said, not hidden.
		err = fmt.Errorf("the pinned hash is gone (both copies) though the install's units are there: %w", err)
	} else {
		rep, err = ensure(l, run, pinned)
	}
	if len(rep.Restored)+len(rep.Started) > 0 || err != nil {
		n := Note{Time: time.Now().UTC(), Restored: rep.Restored, Started: rep.Started}
		if err != nil {
			n.Error = err.Error()
		}
		addNote(l, n)
	}
	return rep, err
}

func ensure(l Layout, run Runner, pinned string) (Report, error) {
	var rep Report
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
		// Queued, not waited for: a guard stopping runs this too, and a
		// waiting start of its own unit would hold that stop until it times out.
		if _, err := run("systemctl", "start", u, "--no-block"); err != nil {
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

// Note is what one ensure had to do: the agent reports it as a tamper
// incident, since nothing put back or started went away by itself.
type Note struct {
	Time     time.Time
	Restored []string `json:",omitempty"`
	Started  []string `json:",omitempty"`
	Error    string   `json:",omitempty"`
}

// maxNotes caps the notes file: a guard that fails every second while the
// agent is down must not fill the disk.
const maxNotes = 1 << 20

// addNote appends n to the notes file, one JSON line, best effort.
func addNote(l Layout, n Note) {
	path := l.p(l.Notes)
	if st, err := os.Stat(path); err == nil && st.Size() > maxNotes {
		return
	}
	b, err := json.Marshal(n)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n')) // one write: appends from several ensures do not interleave
}

// TakeNotes returns the notes left since the last call and removes them.
// The file is renamed first, so a note added meanwhile starts a new one.
func TakeNotes(l Layout) []Note {
	path := l.p(l.Notes)
	taken := path + ".taken"
	if err := os.Rename(path, taken); err != nil {
		return nil
	}
	defer os.Remove(taken)
	b, err := os.ReadFile(taken)
	if err != nil {
		return nil
	}
	var out []Note
	for _, line := range strings.Split(string(b), "\n") {
		var n Note
		if line != "" && json.Unmarshal([]byte(line), &n) == nil {
			out = append(out, n)
		}
	}
	return out
}
