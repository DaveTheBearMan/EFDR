package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pathenc"
)

// quarantineTTL is how long a removed file can still be restored.
const quarantineTTL = 24 * time.Hour

// systemDirs hold the system's own programs: nothing there is removed on an
// order, whatever was reported (/usr/lib/systemd is a persistence site and
// is not one of them).
var systemDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/lib", "/lib64", "/usr/lib", "/usr/libexec", "/boot"}

func systemPath(p string) bool {
	if p == "/usr/lib/systemd" || strings.HasPrefix(p, "/usr/lib/systemd/") {
		return false
	}
	for _, d := range systemDirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// qmeta is what the quarantine keeps of a removed file.
type qmeta struct {
	Path     string
	Mode     uint32
	UID, GID uint32
	Link     string
	SHA256   string
	At       time.Time
}

func (a *agent) qdir(id string) string { return filepath.Join(a.state, "quarantine-files", id) }

// fileOrder acts on a `file` order: remove a file the agent itself
// reported as new, or put a removed one back. The caller holds a.mu.
func (a *agent) fileOrder(id, verdict string) {
	refuse := func(why string) {
		a.record(incident.Incident{Kind: "file-refused", Action: "alert", Severity: model.SevHigh, Detail: fmt.Sprintf("file order %s %s: %s", id, verdict, why)})
	}
	if id == "" || strings.ContainsAny(id, "/.") {
		refuse("bad id")
		return
	}
	switch verdict {
	case "remove":
		if why := a.removeFile(id); why != "" {
			refuse(why)
		}
	case "undo":
		if why := a.restoreFile(id); why != "" {
			refuse(why)
		}
	}
}

func (a *agent) removeFile(id string) string {
	e, ok := a.driftNew[id]
	if !ok {
		return "not a file this agent reported as new"
	}
	switch {
	case systemPath(e.Path):
		return e.Path + " is under a system directory"
	case a.guardedPath(e.Path):
		return e.Path + " is a scored service's binary"
	}
	if a.pol.Base != nil {
		if _, in := a.pol.Base.Files[pathenc.Encode(e.Path)]; in {
			return e.Path + " is in the baseline"
		}
	}
	full := filepath.Join(a.root, e.Path)
	st, err := os.Lstat(full)
	if err != nil {
		return "gone: " + err.Error()
	}
	sys, _ := st.Sys().(*syscall.Stat_t)
	m := qmeta{Path: e.Path, Mode: uint32(st.Mode().Perm()), SHA256: e.SHA256, At: a.now()}
	if sys != nil {
		m.UID, m.GID = sys.Uid, sys.Gid
	}
	switch {
	case e.Type == baseline.TypeLink:
		target, err := os.Readlink(full)
		if err != nil || target != e.Link {
			return "no longer the symlink that was reported"
		}
		m.Link = target
	case e.Type == baseline.TypeFile && st.Mode().IsRegular():
		if sum, err := fileSum(full, e.Size); err != nil || (e.SHA256 != "" && !strings.HasPrefix(e.SHA256, "partial:") && sum != e.SHA256) {
			return "changed since it was reported"
		}
	default:
		return "no longer the file that was reported"
	}
	dir := a.qdir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err.Error()
	}
	if m.Link != "" {
		if err := os.Remove(full); err != nil {
			return err.Error()
		}
	} else if err := moveFile(full, filepath.Join(dir, "data")); err != nil {
		return err.Error()
	}
	meta, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o600); err != nil {
		a.logf("quarantine meta for %s: %v", id, err)
	}
	a.record(incident.Incident{Kind: "file-removed", Action: "repaired", Severity: model.SevHigh, Path: e.Path, SHA256: e.SHA256,
		Detail: "moved to quarantine on the operator's order; restorable for 24 h"})
	return ""
}

func (a *agent) restoreFile(id string) string {
	dir := a.qdir(id)
	b, err := collect.ReadFile(filepath.Join(dir, "meta.json"), 1<<16)
	if err != nil {
		return "nothing in quarantine under that id"
	}
	var m qmeta
	if json.Unmarshal(b, &m) != nil || m.Path == "" || FileID(m.Path) != id {
		return "the quarantine entry is damaged"
	}
	full := filepath.Join(a.root, m.Path)
	if _, err := os.Lstat(full); err == nil {
		return m.Path + " exists again; not overwritten"
	}
	if m.Link != "" {
		if err := os.Symlink(m.Link, full); err != nil {
			return err.Error()
		}
		os.Lchown(full, int(m.UID), int(m.GID))
	} else {
		if err := moveFile(filepath.Join(dir, "data"), full); err != nil {
			return err.Error()
		}
		os.Chmod(full, os.FileMode(m.Mode))
		os.Chown(full, int(m.UID), int(m.GID))
	}
	os.RemoveAll(dir)
	a.record(incident.Incident{Kind: "file-restored", Action: "repaired", Severity: model.SevMedium, Path: m.Path, SHA256: m.SHA256, Detail: "restored from quarantine on the operator's order"})
	return ""
}

// guardedPath reports whether p is a scored service's binary: a guard_exes
// entry, or what a guarded process runs.
func (a *agent) guardedPath(p string) bool {
	if slices.Contains(a.cfg.GuardExes, p) {
		return true
	}
	if a.snap != nil {
		for _, pr := range a.snap.Procs {
			if pr.Exe == p && a.pol.Guarded(a.snap, pr) {
				return true
			}
		}
	}
	return false
}

// purgeQuarantine drops entries older than the TTL. The caller holds a.mu.
func (a *agent) purgeQuarantine() {
	root := filepath.Join(a.state, "quarantine-files")
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range ents {
		b, err := collect.ReadFile(filepath.Join(root, e.Name(), "meta.json"), 1<<16)
		var m qmeta
		if err != nil || json.Unmarshal(b, &m) != nil || a.now().Sub(m.At) > quarantineTTL {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// fileSum is the sha256 of a regular file, read with O_NOFOLLOW; a file
// over 64 MiB is judged by its size alone.
func fileSum(path string, size int64) (string, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("not a regular file")
	}
	if st.Size() > 64<<20 {
		if st.Size() != size {
			return "", fmt.Errorf("size changed")
		}
		return "", nil
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// moveFile renames, or copies and removes across filesystems.
func moveFile(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(to)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(to)
		return err
	}
	return os.Remove(from)
}
