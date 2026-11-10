// Package collect captures a host snapshot from a root directory.
package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"xdr/internal/baseline"
	"xdr/internal/classify"
	"xdr/internal/pathenc"
)

// maxContent is the largest file whose content is kept for byte diffs.
const maxContent = 65536

// maxHash bounds how much of one file is read, so a sparse or
// ever-growing file cannot stall the scan. A larger file is hashed over
// its first maxHash bytes and its SHA256 carries the "partial:" prefix.
var maxHash int64 = 1 << 30

const privBits = uint32(os.ModeSetuid | os.ModeSetgid)

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if classify.Match(pat, p) {
			return true
		}
	}
	return false
}

// Walk records the filesystem under root (see Skipped, Sealed, Volatile and
// Ignored for what is left out). It never follows symlinks and opens only
// regular files. An object it could not read is still recorded, with Err
// set; the same errors are returned as text.
func Walk(root string) (map[string]baseline.FileEntry, []string) {
	root = filepath.Clean(root)
	files := map[string]baseline.FileEntry{}
	var errs []string
	fail := func(rel string, e baseline.FileEntry, err error) {
		e.Err = errText(err)
		files[pathenc.Encode(rel)] = e
		errs = append(errs, fmt.Sprintf("%s: %s", rel, e.Err))
	}
	skipDir := func(d fs.DirEntry) error {
		if d != nil && d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	filepath.WalkDir(root, func(full string, d fs.DirEntry, err error) error {
		rel := relPath(root, full)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			// A directory that could not be listed: the entry made on the
			// way in (if it was recorded) now carries the error.
			if rel == "" {
				rel = "/"
			}
			e := files[pathenc.Encode(rel)]
			if e.Type == 0 {
				e.Type = baseline.TypeDir
			}
			fail(rel, e, err)
			return skipDir(d)
		}
		if rel == "" {
			return nil // the root itself
		}
		if matchAny(Skipped, rel) {
			return skipDir(d)
		}
		info, err := os.Lstat(full)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // vanished mid-walk
		}
		if err != nil {
			fail(rel, baseline.FileEntry{}, err)
			return skipDir(d)
		}
		e := meta(info)
		mode := info.Mode()
		if mode.IsRegular() {
			e.Caps = caps(full)
		}
		if mode.IsDir() && (matchAny(Sealed, rel) || pseudoFS(full)) {
			files[pathenc.Encode(rel)] = e
			return filepath.SkipDir
		}
		if !keep(rel, e) {
			return nil
		}
		switch {
		case mode.IsRegular():
			content := e.Size <= maxContent && classify.Path(rel).KeepContent
			e.SHA256, e.Content, err = hashFile(full, content)
		case mode&os.ModeSymlink != 0:
			var target string
			target, err = os.Readlink(full)
			e.Link = pathenc.Encode(target)
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil // vanished mid-walk
		}
		if err != nil {
			fail(rel, e, err)
			return nil
		}
		files[pathenc.Encode(rel)] = e
		return nil
	})
	return files, errs
}

// relPath turns a walked path into a path relative to root with a leading
// slash; the root itself is "".
func relPath(root, full string) string {
	if full == root {
		return ""
	}
	if root == "/" {
		return full
	}
	return strings.TrimPrefix(full, root)
}

// keep decides whether an object is part of the snapshot.
func keep(rel string, e baseline.FileEntry) bool {
	regular := e.Type == baseline.TypeFile
	privileged := regular && (e.Mode&privBits != 0 || e.Caps != "")
	switch {
	case rel == "/dev" || strings.HasPrefix(rel, "/dev/") && rel != "/dev/shm" && !strings.HasPrefix(rel, "/dev/shm/"):
		// Device nodes come and go with hardware; a regular file in the
		// device tree is a hiding place.
		return regular
	case volatile(rel):
		return privileged || classify.Path(rel).Category != classify.Fallback
	case matchAny(Ignored, rel):
		return !regular || privileged
	}
	return true
}

func volatile(rel string) bool {
	for _, pat := range Volatile {
		if classify.Match(pat+"/**", rel) {
			return true
		}
	}
	return false
}

// pseudoFS reports whether dir is the root of, or inside, a kernel
// filesystem that has no files to inventory and can produce endless data.
func pseudoFS(dir string) bool {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return false
	}
	switch int64(st.Type) {
	case unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC, unix.CGROUP_SUPER_MAGIC, unix.CGROUP2_SUPER_MAGIC,
		unix.DEBUGFS_MAGIC, unix.TRACEFS_MAGIC, unix.SECURITYFS_MAGIC:
		return true
	}
	return false
}

func meta(info fs.FileInfo) baseline.FileEntry {
	e := baseline.FileEntry{Mode: uint32(info.Mode()), Size: info.Size()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
	}
	switch {
	case info.Mode().IsRegular():
		e.Type = baseline.TypeFile
	case info.IsDir():
		e.Type = baseline.TypeDir
	case info.Mode()&os.ModeSymlink != 0:
		e.Type = baseline.TypeLink
	default:
		e.Type = baseline.TypeOther
	}
	return e
}

func hashFile(full string, content bool) (string, []byte, error) {
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	// Re-check after open: the path may have been swapped for a fifo or device.
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", nil, errors.New("not a regular file after open")
	}
	return digest(f, content)
}

// capped keeps what is written to it until that exceeds maxContent, then
// keeps nothing: the file grew after it was measured.
type capped struct {
	buf  bytes.Buffer
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > maxContent {
		c.over = true
		c.buf.Reset()
	}
	if !c.over {
		c.buf.Write(p)
	}
	return len(p), nil
}

// digest hashes up to maxHash bytes of r, also returning them when content
// is wanted and they fit in maxContent.
func digest(r io.Reader, content bool) (string, []byte, error) {
	h := sha256.New()
	var c capped
	var w io.Writer = h
	if content {
		w = io.MultiWriter(h, &c)
	}
	n, err := io.Copy(w, io.LimitReader(r, maxHash))
	if err != nil {
		return "", nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if n == maxHash {
		var one [1]byte
		if m, _ := io.ReadFull(r, one[:]); m > 0 {
			sum = "partial:" + sum
		}
	}
	if !content || c.over {
		return sum, nil, nil
	}
	if c.buf.Len() == 0 {
		return sum, []byte{}, nil
	}
	return sum, c.buf.Bytes(), nil
}

func caps(full string) string {
	buf := make([]byte, 64)
	n, err := unix.Lgetxattr(full, "security.capability", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return hex.EncodeToString(buf[:n])
}
