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

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if classify.Match(pat, p) {
			return true
		}
	}
	return false
}

// Walk records every filesystem object under root except Excluded and
// Ignored paths. It never follows symlinks and opens only regular files.
func Walk(root string) (map[string]baseline.FileEntry, []string) {
	root = filepath.Clean(root)
	files := map[string]baseline.FileEntry{}
	var errs []string
	fail := func(p string, err error) {
		errs = append(errs, fmt.Sprintf("%s: %v", p, err))
	}

	filepath.WalkDir(root, func(full string, d fs.DirEntry, err error) error {
		rel := relPath(root, full)
		if rel == "" {
			return nil // the root itself
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			fail(rel, err)
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "/dev" {
			return nil // descend for /dev/shm, but don't record /dev
		}
		if matchAny(Ignored, rel) {
			return nil
		}
		e, err := entry(full, rel)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // vanished mid-walk
		}
		if err != nil {
			e.Err = err.Error()
			fail(rel, err)
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

func skip(rel string) bool {
	if strings.HasPrefix(rel, "/dev/") && rel != "/dev/shm" && !strings.HasPrefix(rel, "/dev/shm/") {
		return true
	}
	return matchAny(Excluded, rel)
}

func entry(full, rel string) (baseline.FileEntry, error) {
	var e baseline.FileEntry
	info, err := os.Lstat(full)
	if err != nil {
		return e, err
	}
	e.Mode = uint32(info.Mode())
	e.Size = info.Size()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
	}
	e.Caps = caps(full)
	switch {
	case info.Mode().IsRegular():
		e.Type = baseline.TypeFile
		keep := e.Size <= maxContent && classify.Path(rel).KeepContent
		e.SHA256, e.Content, err = hashFile(full, keep)
		return e, err
	case info.IsDir():
		e.Type = baseline.TypeDir
	case info.Mode()&os.ModeSymlink != 0:
		e.Type = baseline.TypeLink
		e.Link, err = os.Readlink(full)
		return e, err
	default:
		e.Type = baseline.TypeOther
	}
	return e, nil
}

func hashFile(full string, keep bool) (string, []byte, error) {
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	// Re-check after open: the path may have been swapped for a fifo or device.
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return "", nil, fmt.Errorf("not a regular file after open")
	}
	h := sha256.New()
	var buf bytes.Buffer
	var w io.Writer = h
	if keep {
		w = io.MultiWriter(h, &buf)
	}
	if _, err := io.Copy(w, f); err != nil {
		return "", nil, err
	}
	var content []byte
	if keep {
		content = buf.Bytes()
		if content == nil {
			content = []byte{}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), content, nil
}

func caps(full string) string {
	buf := make([]byte, 64)
	n, err := unix.Lgetxattr(full, "security.capability", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return hex.EncodeToString(buf[:n])
}
