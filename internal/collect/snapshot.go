package collect

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xdr/internal/baseline"
)

// Read limits for the files a snapshot opens by name.
const (
	maxDB    = 8 << 20 // passwd, shadow, group, /proc/modules
	maxSmall = 64 << 10
)

// Snapshot captures the full host state visible under root. Files it
// expects but cannot read safely are listed in Errors; absent files are
// simply not captured.
func Snapshot(root string) (*baseline.Baseline, error) {
	root, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	b := &baseline.Baseline{Schema: 1, CapturedAt: time.Now().UTC()}
	b.Files, _ = Walk(root)

	read := func(rel string, max int64) []byte {
		data, err := ReadFile(filepath.Join(root, rel), max)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				b.Errors = append(b.Errors, fmt.Sprintf("/%s: %s", rel, errText(err)))
			}
			return nil
		}
		if data == nil {
			data = []byte{}
		}
		return data
	}
	if data := read("etc/passwd", maxDB); data != nil {
		b.Accounts = ParsePasswd(bytes.NewReader(data))
		if s := read("etc/shadow", maxDB); s != nil {
			ApplyShadow(b.Accounts, bytes.NewReader(s))
		}
	}
	if data := read("etc/group", maxDB); data != nil {
		b.Groups = ParseGroup(bytes.NewReader(data))
	}
	if data := read("proc/modules", maxDB); data != nil {
		b.Modules = parseModules(data)
	}
	b.Host = strings.TrimSpace(string(read("etc/hostname", 4096)))
	// /etc/os-release is a symlink to this file on Ubuntu; read the target
	// by name rather than follow a link.
	rel := read("usr/lib/os-release", maxSmall)
	if rel == nil {
		rel = read("etc/os-release", maxSmall)
	}
	b.OSRelease = osVersion(rel)
	return b, nil
}

// resolveRoot turns the --root argument into a real absolute directory, so
// a relative path or a symlink to the root scans the same tree, and a
// missing one is an error instead of an empty (clean-looking) snapshot.
func resolveRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("root %s is not a directory", root)
	}
	return abs, nil
}

func osVersion(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "VERSION="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
