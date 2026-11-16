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
	"sync"
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

// SafePath is where the tools XDR runs are looked up: the system's own
// directories, never the inherited $PATH. It is also the children's PATH.
const SafePath = "/usr/sbin:/usr/bin:/sbin:/bin"

// safeEnv is the whole environment a child gets: nothing inherited, so no
// LD_PRELOAD and no $PATH of the caller's.
var safeEnv = []string{"PATH=" + SafePath, "LANG=C", "LC_ALL=C"}

var (
	toolMu sync.Mutex
	tools  = map[string]string{} // "dirs|name" → absolute path, resolved once
)

// lookTool finds name in dirs (an absolute name is taken as it is).
func lookTool(dirs []string, name string) (string, error) {
	if strings.Contains(name, "/") {
		if !filepath.IsAbs(name) {
			return "", fmt.Errorf("%s: not an absolute path", name)
		}
		return name, nil
	}
	key := strings.Join(dirs, ":") + "|" + name
	toolMu.Lock()
	defer toolMu.Unlock()
	if p, ok := tools[key]; ok {
		return p, nil
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			tools[key] = p
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in %s", name, strings.Join(dirs, ":"))
}

func commandIn(dirs []string, name string, args ...string) *exec.Cmd {
	c := &exec.Cmd{Args: append([]string{name}, args...), Env: safeEnv}
	c.Path, c.Err = lookTool(dirs, name)
	if c.Err != nil {
		c.Path = name
	}
	return c
}

// Command is exec.Command with the tool looked up in SafePath only and a
// fixed minimal environment.
func Command(name string, args ...string) *exec.Cmd {
	return commandIn(filepath.SplitList(SafePath), name, args...)
}

func runnerIn(dirs []string) Runner {
	return func(name string, args ...string) ([]byte, error) {
		return commandIn(dirs, name, args...).CombinedOutput()
	}
}

// ExecRunner runs the command for real, by its path in SafePath.
func ExecRunner(name string, args ...string) ([]byte, error) {
	return Command(name, args...).CombinedOutput()
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
