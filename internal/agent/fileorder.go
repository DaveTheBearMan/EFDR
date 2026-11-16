package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

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
	// Everything below happens through descriptors: the parent directories
	// are opened without following a symlink, the file is checked and hashed
	// from the descriptor it was opened as, and moved by name inside the
	// directory that was opened.
	dirfd, err := openDirNoFollow(a.root, filepath.Dir(e.Path))
	if err != nil {
		return "the directory cannot be opened without following a symlink: " + err.Error()
	}
	defer unix.Close(dirfd)
	name := filepath.Base(e.Path)
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return "gone: " + err.Error()
	}
	m := qmeta{Path: e.Path, Mode: st.Mode & 0o777, UID: st.Uid, GID: st.Gid, SHA256: e.SHA256, At: a.now()}
	qdir := a.qdir(id)
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return err.Error()
	}
	qfd, err := unix.Open(qdir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err.Error()
	}
	defer unix.Close(qfd)
	switch {
	case e.Type == baseline.TypeLink && st.Mode&unix.S_IFMT == unix.S_IFLNK:
		buf := make([]byte, 4096)
		n, err := unix.Readlinkat(dirfd, name, buf)
		if err != nil || string(buf[:n]) != e.Link {
			return "no longer the symlink that was reported"
		}
		m.Link = e.Link
		if err := unix.Unlinkat(dirfd, name, 0); err != nil {
			return err.Error()
		}
	case e.Type == baseline.TypeFile && st.Mode&unix.S_IFMT == unix.S_IFREG:
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err.Error()
		}
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		var fst unix.Stat_t
		if err := unix.Fstat(fd, &fst); err != nil || fst.Dev != st.Dev || fst.Ino != st.Ino || fst.Mode&unix.S_IFMT != unix.S_IFREG {
			return "no longer the file that was reported"
		}
		if sum, err := fileSumFrom(f, fst.Size, e.Size); err != nil || (e.SHA256 != "" && !strings.HasPrefix(e.SHA256, "partial:") && sum != e.SHA256) {
			return "changed since it was reported"
		}
		if err := unix.Renameat(dirfd, name, qfd, "data"); err != nil {
			if !errors.Is(err, unix.EXDEV) {
				return err.Error()
			}
			// Another filesystem: copy from the descriptor, then unlink the
			// name only if it is still the file that was copied.
			if err := copyFd(f, qfd, "data"); err != nil {
				return err.Error()
			}
			var now unix.Stat_t
			if err := unix.Fstatat(dirfd, name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil || now.Dev != fst.Dev || now.Ino != fst.Ino {
				unix.Unlinkat(qfd, "data", 0)
				return "changed while it was moved"
			}
			if err := unix.Unlinkat(dirfd, name, 0); err != nil {
				return err.Error()
			}
		}
	default:
		return "no longer the file that was reported"
	}
	meta, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(qdir, "meta.json"), meta, 0o600); err != nil {
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
	dirfd, err := openDirNoFollow(a.root, filepath.Dir(m.Path))
	if err != nil {
		return "the directory cannot be opened without following a symlink: " + err.Error()
	}
	defer unix.Close(dirfd)
	name := filepath.Base(m.Path)
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return m.Path + " exists again; not overwritten"
	}
	qfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err.Error()
	}
	defer unix.Close(qfd)
	if m.Link != "" {
		if err := unix.Symlinkat(m.Link, dirfd, name); err != nil {
			return err.Error()
		}
		unix.Fchownat(dirfd, name, int(m.UID), int(m.GID), unix.AT_SYMLINK_NOFOLLOW)
	} else {
		// Owner and mode are set on the quarantined file, which only root
		// can reach, before it is moved: nothing is chowned by name in a
		// directory the user owns. The move refuses to replace anything.
		fd, err := unix.Openat(qfd, "data", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err.Error()
		}
		f := os.NewFile(uintptr(fd), "data")
		defer f.Close()
		f.Chown(int(m.UID), int(m.GID))
		f.Chmod(os.FileMode(m.Mode & 0o777))
		if err := unix.Renameat2(qfd, "data", dirfd, name, unix.RENAME_NOREPLACE); err != nil {
			if !errors.Is(err, unix.EXDEV) {
				return err.Error()
			}
			if err := copyFdTo(f, dirfd, name, os.FileMode(m.Mode&0o777), int(m.UID), int(m.GID)); err != nil {
				return err.Error()
			}
			unix.Unlinkat(qfd, "data", 0)
		}
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

// fileSumFrom is the sha256 of an open regular file; one over 64 MiB is
// judged by its size alone (size is its size now, reported what was reported).
func fileSumFrom(f *os.File, size, reported int64) (string, error) {
	if size > 64<<20 {
		if size != reported {
			return "", fmt.Errorf("size changed")
		}
		return "", nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyFd copies f into a new file name inside the directory qfd (mode 0600).
func copyFd(f *os.File, qfd int, name string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return copyFdTo(f, qfd, name, 0o600, -1, -1)
}

// copyFdTo makes a new file name in the directory dirfd (it must not exist,
// and a symlink is not followed) with f's content, owner and mode.
func copyFdTo(f *os.File, dirfd int, name string, mode os.FileMode, uid, gid int) error {
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	out := os.NewFile(uintptr(fd), name)
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		_, err = io.Copy(out, f)
	}
	if uid >= 0 {
		out.Chown(uid, gid)
	}
	out.Chmod(mode)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		unix.Unlinkat(dirfd, name, 0)
	}
	return err
}
