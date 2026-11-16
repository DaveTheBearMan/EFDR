// Package install puts the agent on a box so that it stays: three copies of
// the binary, a pinned hash, a manifest of everything installed, and six
// kinds of launch point that each pick a good copy and run `xdr ensure`.
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Layout is where everything goes. Root is "" on a box and a temporary
// directory in tests; the paths are as the box sees them.
type Layout struct {
	Root     string
	Copies   []string // the binary, three times
	Pinned   string   // the binary's sha256
	Manifest string
	Backup   string // directory: what ensure restores from
	Config   string // the agent's config (and Config+".sig")
	FleetDir string // ca.pem, host.pem, host-key.pem, rules.pub
	Notes    string // what ensure had to do, for the agent to report
}

// DefaultLayout is the layout of a box.
func DefaultLayout() Layout {
	return Layout{
		Copies:   []string{"/usr/local/sbin/xdr", "/usr/lib/xdr/xdr", "/var/lib/xdr/bin/xdr"},
		Pinned:   "/etc/xdr/pinned.sha256",
		Manifest: "/var/lib/xdr/manifest.json",
		Backup:   "/var/lib/xdr/backup",
		Config:   "/etc/xdr/agent.json",
		FleetDir: "/etc/xdr/fleet",
		Notes:    "/var/lib/xdr/ensure-notes.jsonl",
	}
}

func (l Layout) p(path string) string { return filepath.Join(l.Root, path) }

// Runner runs a command and returns what it printed.
type Runner func(name string, args ...string) ([]byte, error)

// ExecRunner runs the command for real.
func ExecRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Units are the units install enables and ensure keeps running.
var Units = []string{"xdr-agent.service", "xdr-guard-a.service", "xdr-guard-b.service", "xdr-ensure.timer"}

// Entry is one file install put down.
type Entry struct {
	Path   string
	SHA256 string
	Mode   uint32
	Kind   string // copy, file, config, backup
	Source string // for config and backup: the other half of the pair
}

// Manifest is what install put down.
type Manifest struct{ Entries []Entry }

// Report is what an install or an ensure did.
type Report struct {
	Wrote    []string // install
	Restored []string // ensure
	Started  []string // ensure
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// ReadManifest reads the manifest, or its copy in the backup directory.
func ReadManifest(l Layout) (Manifest, error) {
	var m Manifest
	b, err := readFile(l.p(l.Manifest))
	if errors.Is(err, fs.ErrNotExist) {
		b, err = readFile(l.p(l.Backup + "/manifest.json"))
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	return m, nil
}

// pinnedHash is the pinned hash, from its file or the backup's copy.
func pinnedHash(l Layout) (string, error) {
	b, err := readFile(l.p(l.Pinned))
	if errors.Is(err, fs.ErrNotExist) {
		b, err = readFile(l.p(l.Backup + "/pinned.sha256"))
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// atomic writes content to path through a temporary name and a rename.
func atomic(path string, content []byte, mode fs.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".xdr-new"
	if err := os.WriteFile(tmp, content, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
