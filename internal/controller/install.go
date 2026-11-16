package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"xdr/internal/install"
	"xdr/internal/pki"
)

// ControllerUnitName is the controller's systemd unit.
const ControllerUnitName = "xdr-controller.service"

// ControllerLayout is where `xdr controller install` writes on the jump
// box. Root is "" on a box and a temporary directory in tests.
type ControllerLayout struct {
	Root string
	Bin  string // the installed binary
	Unit string // the unit file
}

// DefaultControllerLayout is the layout of a jump box.
func DefaultControllerLayout() ControllerLayout {
	return ControllerLayout{Bin: "/usr/local/sbin/xdr", Unit: "/etc/systemd/system/" + ControllerUnitName}
}

func (l ControllerLayout) p(path string) string { return filepath.Join(l.Root, path) }

// InstallOptions is what `xdr controller install` was given.
type InstallOptions struct {
	Dir           string   // the controller directory, absolute
	Name          string   // the address agents reach the controller at
	ConsoleListen string   // "": the config's, or Name:8443
	Protect       []string // further addresses no rule may name
	Recovery      string
	Auto, Gray    []string
	ResetPassword bool   // set the console password although one is set
	Binary        string // the binary to install
	// Password is asked only when a password is to be set.
	Password    func() (string, error)
	SetPassword func(dir, password string) error
}

// InstallReport is what an install did. The password is never in it.
type InstallReport struct {
	Initialised bool
	PasswordSet bool
	Wrote       []string
	Restarted   bool
}

// ControllerUnit is the controller's unit file. It has no ordering on the
// network: started before its address is up, it fails and is restarted
// until it binds, for as long as it takes.
func ControllerUnit(bin, dir string) string {
	return "[Unit]\nDescription=XDR controller (etcd, rule promotion, web console)\nStartLimitIntervalSec=0\n\n" +
		"[Service]\nExecStart=" + bin + " controller run --dir " + dir + "\nRestart=always\nRestartSec=2\nLimitNOFILE=65536\n\n" +
		"[Install]\nWantedBy=multi-user.target\n"
}

// InstallController makes Dir a controller directory if it is not one,
// merges the options into its controller.json (never dropping a key), sets
// the console password when none is set (or ResetPassword), puts the
// binary and the unit down and starts the unit. Run again with nothing
// changed, it changes nothing. Everything is checked before anything is
// written.
func InstallController(l ControllerLayout, run install.Runner, o InstallOptions) (InstallReport, error) {
	var rep InstallReport
	addr, err := netip.ParseAddr(o.Name)
	if err != nil {
		return rep, fmt.Errorf("--name %q: not an IP address (agents dial it and it is protected)", o.Name)
	}
	if !filepath.IsAbs(o.Dir) || strings.ContainsAny(o.Dir, " \t\n\"'\\$%;") {
		return rep, fmt.Errorf("--dir %q: an absolute path without spaces or quotes is needed (it goes in the unit)", o.Dir)
	}
	o.Dir = filepath.Clean(o.Dir)
	if o.ConsoleListen != "" {
		if _, _, err := net.SplitHostPort(o.ConsoleListen); err != nil {
			return rep, fmt.Errorf("--console-listen %q: %w", o.ConsoleListen, err)
		}
	}
	protect := []string{addr.String()}
	for _, p := range o.Protect {
		if _, err := netip.ParsePrefix(p); err != nil {
			if _, err := netip.ParseAddr(p); err != nil {
				return rep, fmt.Errorf("--protect %q: not an address or CIDR", p)
			}
		}
		protect = append(protect, p)
	}
	bin, err := os.ReadFile(o.Binary)
	if err != nil {
		return rep, err
	}
	cfgPath := filepath.Join(o.Dir, "controller.json")
	merged, old, err := mergeConfig(cfgPath, o, addr, protect)
	if err != nil {
		return rep, err
	}
	var pw string
	if _, err := os.Stat(filepath.Join(o.Dir, "console.json")); o.ResetPassword || err != nil {
		if pw, err = o.Password(); err != nil {
			return rep, fmt.Errorf("reading the console password: %w", err)
		}
		if pw == "" {
			return rep, errors.New("the console password is empty; give it on stdin")
		}
	}
	// Checked: now the changes.
	if _, err := os.Stat(filepath.Join(o.Dir, "ca-key.pem")); errors.Is(err, fs.ErrNotExist) {
		if err := pki.Init(o.Dir, []string{addr.String()}); err != nil {
			return rep, err
		}
		rep.Initialised = true
	}
	changed := rep.Initialised
	if !bytes.Equal(merged, old) {
		if err := writeChecked(cfgPath, merged); err != nil {
			return rep, err
		}
		rep.Wrote = append(rep.Wrote, cfgPath)
		changed = true
	}
	if pw != "" {
		if err := o.SetPassword(o.Dir, pw); err != nil {
			return rep, err
		}
		rep.PasswordSet = true
	}
	_, unitErr := os.Stat(l.p(l.Unit))
	unitWasThere := unitErr == nil
	for _, f := range []struct {
		path    string
		content []byte
		mode    fs.FileMode
	}{
		{l.Bin, bin, 0o755},
		{l.Unit, []byte(ControllerUnit(l.Bin, o.Dir)), 0o644},
	} {
		if cur, err := os.ReadFile(l.p(f.path)); err == nil && bytes.Equal(cur, f.content) {
			continue
		}
		if err := writeAtomic(l.p(f.path), f.content, f.mode); err != nil {
			return rep, err
		}
		rep.Wrote = append(rep.Wrote, f.path)
		changed = true
	}
	if changed {
		if out, err := run("systemctl", "daemon-reload"); err != nil {
			return rep, fmt.Errorf("systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := run("systemctl", "enable", "--now", ControllerUnitName); err != nil {
		return rep, fmt.Errorf("systemctl enable --now: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if changed && unitWasThere {
		if out, err := run("systemctl", "restart", ControllerUnitName); err != nil {
			return rep, fmt.Errorf("systemctl restart: %v: %s", err, strings.TrimSpace(string(out)))
		}
		rep.Restarted = true
	}
	return rep, nil
}

// mergeConfig is path's controller.json with the options merged in, and
// the file as it was re-encoded the same way (nil when there is none).
func mergeConfig(path string, o InstallOptions, addr netip.Addr, protect []string) (merged, old []byte, err error) {
	m := map[string]json.RawMessage{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		if old, err = encode(m); err != nil {
			return nil, nil, err
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, err
	}
	set := func(k string, v any) error {
		raw, err := json.Marshal(v)
		m[k] = raw
		return err
	}
	union := func(k string, add []string) error {
		var cur []string
		if raw, ok := m[k]; ok && string(raw) != "null" {
			if err := json.Unmarshal(raw, &cur); err != nil {
				return fmt.Errorf("%s: %s: %w", path, k, err)
			}
		}
		n := len(cur)
		for _, a := range add {
			if !slices.Contains(cur, a) {
				cur = append(cur, a)
			}
		}
		if _, ok := m[k]; ok && len(cur) == n {
			return nil // as it was, byte for byte
		}
		if len(cur) == 0 {
			return nil
		}
		return set(k, cur)
	}
	if _, ok := m["listen"]; !ok {
		if err := set("listen", net.JoinHostPort(addr.String(), "2379")); err != nil {
			return nil, nil, err
		}
	}
	console := map[string]json.RawMessage{}
	if raw, ok := m["console"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &console); err != nil {
			return nil, nil, fmt.Errorf("%s: console: %w", path, err)
		}
	}
	_, hasListen := console["listen"]
	if o.ConsoleListen != "" || !hasListen {
		l := o.ConsoleListen
		if l == "" {
			l = net.JoinHostPort(addr.String(), "8443")
		}
		raw, _ := json.Marshal(l)
		if string(console["listen"]) != string(raw) {
			console["listen"] = raw
			if err := set("console", console); err != nil {
				return nil, nil, err
			}
		}
	}
	if o.Recovery != "" {
		if err := set("recovery", o.Recovery); err != nil {
			return nil, nil, err
		}
	}
	for k, add := range map[string][]string{"protect": protect, "gray_users": o.Gray, "auto": o.Auto} {
		if err := union(k, add); err != nil {
			return nil, nil, err
		}
	}
	merged, err = encode(m)
	return merged, old, err
}

func encode(m map[string]json.RawMessage) ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// writeChecked puts a controller.json down only if LoadConfig takes it.
func writeChecked(path string, content []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		return err
	}
	if _, err := LoadConfig(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func writeAtomic(path string, content []byte, mode fs.FileMode) error {
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
