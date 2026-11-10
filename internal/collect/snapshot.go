package collect

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xdr/internal/baseline"
)

// Snapshot captures the full host state visible under root.
func Snapshot(root string) (*baseline.Baseline, error) {
	b := &baseline.Baseline{Schema: 1, CapturedAt: time.Now().UTC()}
	b.Files, b.Errors = Walk(root)

	etc := func(name string) string { return filepath.Join(root, "etc", name) }
	if f, err := os.Open(etc("passwd")); err == nil {
		b.Accounts = ParsePasswd(f)
		f.Close()
		if s, err := os.Open(etc("shadow")); err == nil {
			ApplyShadow(b.Accounts, s)
			s.Close()
		}
	}
	if f, err := os.Open(etc("group")); err == nil {
		b.Groups = ParseGroup(f)
		f.Close()
	}
	b.Modules = Modules(root)
	if h, err := os.ReadFile(etc("hostname")); err == nil {
		b.Host = strings.TrimSpace(string(h))
	}
	b.OSRelease = osVersion(etc("os-release"))
	return b, nil
}

func osVersion(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "VERSION="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
