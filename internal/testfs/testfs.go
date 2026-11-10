// Package testfs builds fixture filesystem trees for tests.
package testfs

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Root returns a fresh temporary root directory.
func Root(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func mkparent(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
}

// File writes content at root/rel with mode, creating parent directories.
func File(t *testing.T, root, rel, content string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	mkparent(t, p)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// Chmod after write: WriteFile's mode is filtered by umask and ignores setuid.
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// Symlink creates root/rel pointing at target.
func Symlink(t *testing.T, root, rel, target string) {
	t.Helper()
	p := filepath.Join(root, rel)
	mkparent(t, p)
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
}

// Fifo creates a named pipe at root/rel.
func Fifo(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	mkparent(t, p)
	if err := unix.Mkfifo(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Remove deletes root/rel.
func Remove(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.Remove(filepath.Join(root, rel)); err != nil {
		t.Fatal(err)
	}
}
