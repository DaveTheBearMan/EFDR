package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"xdr/internal/config"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

const (
	reinstallEvery   = 5 * time.Minute  // at most one reinstall per host in this time
	reinstallTimeout = 10 * time.Minute // one reinstall, binary and all
	defaultAfter     = 60 * time.Second
)

// ReinstallConfig is the reinstall section of controller.json: how to reach
// the boxes the controller may put the agent back on.
type ReinstallConfig struct {
	Key   string                   `json:"key"`   // ssh private key file, absolute; only ever ssh -i's argument
	User  string                   `json:"user"`  // default root
	After config.Duration          `json:"after"` // silence before an automatic reinstall; default 60s
	Hosts map[string]ReinstallHost `json:"hosts"` // by enrolled host name
}

// ReinstallHost is one box that may be reinstalled.
type ReinstallHost struct {
	Addr   string `json:"addr"`   // IP address or DNS name
	Config string `json:"config"` // the host's agent config, absolute
}

var sshUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validAddr is an IP address or a DNS name, nothing a shell or ssh could
// read as anything else.
func validAddr(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	return config.Hostname(s)
}

// check applies the defaults and refuses what must never reach ssh.
func (r *ReinstallConfig) check() error {
	if !filepath.IsAbs(r.Key) {
		return fmt.Errorf("key %q is not an absolute path", r.Key)
	}
	if r.User == "" {
		r.User = "root"
	}
	if !sshUser.MatchString(r.User) {
		return fmt.Errorf("user %q is not a user name", r.User)
	}
	if r.After.Duration < 0 {
		return fmt.Errorf("after is negative")
	}
	if r.After.Duration == 0 {
		r.After.Duration = defaultAfter
	}
	for h, e := range r.Hosts {
		if !config.Hostname(h) {
			return fmt.Errorf("host %q is not a host name", h)
		}
		if !validAddr(e.Addr) {
			return fmt.Errorf("host %s: addr %q is neither an address nor a name", h, e.Addr)
		}
		if !filepath.IsAbs(e.Config) {
			return fmt.Errorf("host %s: config %q is not an absolute path", h, e.Config)
		}
	}
	return nil
}

// SSH runs a command on a box and feeds it stdin.
type SSH interface {
	Run(ctx context.Context, addr, command string, stdin io.Reader) error
}

// ExecSSH is the real SSH: the local ssh client, with the key as its -i.
// The key is read by that process alone; nothing of it crosses the wire.
type ExecSSH struct{ Key, User string }

// Run implements SSH.
func (e ExecSSH) Run(ctx context.Context, addr, command string, stdin io.Reader) error {
	if !filepath.IsAbs(e.Key) || !sshUser.MatchString(e.User) || !validAddr(addr) {
		return errors.New("ssh: refusing an unchecked key, user or address")
	}
	cmd := exec.CommandContext(ctx, "ssh", "-i", e.Key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", e.User+"@"+addr, command)
	cmd.Stdin = stdin
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ssh %s: %w: %s", addr, err, bytes.TrimSpace(out[max(0, len(out)-512):]))
	}
	return nil
}

// script is the whole of what runs on the box. It holds no value from the
// controller's side, and no single quote (sudo's sh -c wraps it in two):
// the host's files arrive as a tar on stdin.
const script = `set -e
d=$(mktemp -d)
trap "rm -rf \"\$d\"" EXIT
tar -x -f - -C "$d"
mkdir -p /etc/xdr
chattr -i -R /etc/xdr/fleet /etc/xdr/agent.json /etc/xdr/agent.json.sig 2>/dev/null || true
rm -rf /etc/xdr/fleet
mv "$d/fleet" /etc/xdr/fleet
cp "$d/agent.json" /etc/xdr/agent.json
cp "$d/agent.json.sig" /etc/xdr/agent.json.sig
chmod 600 /etc/xdr/agent.json /etc/xdr/agent.json.sig
chmod 700 /etc/xdr/fleet
chmod 700 "$d/xdr"
"$d/xdr" install --config /etc/xdr/agent.json`

// Reinstall puts the agent back on host: its binary, a fresh enrolment
// bundle, its signed config, then `xdr install` there. One SSH session
// carries it all, as a tar on stdin into a mktemp -d directory.
func Reinstall(ctx context.Context, dir string, cfg *Config, host string, ssh SSH, binary string) error {
	if cfg == nil || cfg.Reinstall == nil {
		return errors.New("reinstall is not configured")
	}
	rc := cfg.Reinstall
	if err := rc.check(); err != nil {
		return err
	}
	if !config.Hostname(host) {
		return fmt.Errorf("bad host name %q", host)
	}
	hosts, err := pki.Hosts(dir)
	if err != nil {
		return err
	}
	if !slices.Contains(hosts, host) {
		return fmt.Errorf("%s is not enrolled", host)
	}
	h, ok := rc.Hosts[host]
	if !ok {
		return fmt.Errorf("%s is not under reinstall.hosts", host)
	}
	key, err := rules.LoadPrivate(filepath.Join(dir, "rules.key"))
	if err != nil {
		return err
	}
	conf, err := os.ReadFile(h.Config)
	if err != nil {
		return err
	}
	bin, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "xdr-reinstall-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "fleet")
	if err := pki.Enroll(dir, host, bundle); err != nil {
		return err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	put := func(name string, data []byte, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data))}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := put("xdr", bin, 0o700); err != nil {
		return err
	}
	if err := put("agent.json", conf, 0o600); err != nil {
		return err
	}
	if err := put("agent.json.sig", config.Signature(conf, key), 0o600); err != nil {
		return err
	}
	for _, n := range []string{"ca.pem", "host.pem", "host-key.pem", "rules.pub"} {
		b, err := os.ReadFile(filepath.Join(bundle, n))
		if err != nil {
			return err
		}
		if err := put("fleet/"+n, b, 0o600); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	cmd := script
	if rc.User != "root" {
		cmd = "sudo -n sh -c '" + script + "'" // the script holds no single quote, which this wrapper needs
	}
	return ssh.Run(ctx, h.Addr, cmd, &buf)
}

// EnableReinstall makes the controller reinstall hosts listed in
// cfg.Reinstall after they have been silent for its After. binary is the
// file pushed to the box.
func (ctl *Controller) EnableReinstall(cfg *Config, ssh SSH, binary string) {
	ctl.bmu.Lock()
	defer ctl.bmu.Unlock()
	if cfg == nil || cfg.Reinstall == nil {
		return
	}
	ctl.rcfg, ctl.rssh, ctl.rbinary = cfg.Reinstall, ssh, binary
	ctl.rlast = map[string]time.Time{}
}

// checkReinstall starts a reinstall, in its own goroutine, for each listed
// host silent for After: once per silence, and at most once per
// reinstallEvery per host.
func (ctl *Controller) checkReinstall() {
	ctl.bmu.Lock()
	defer ctl.bmu.Unlock()
	if ctl.rcfg == nil {
		return
	}
	now := ctl.now()
	for h, b := range ctl.beats {
		if !b.silent || b.reinstalled || now.Sub(b.silentAt) < ctl.rcfg.After.Duration {
			continue
		}
		if _, ok := ctl.rcfg.Hosts[h]; !ok {
			continue
		}
		if last, ok := ctl.rlast[h]; ok && now.Sub(last) < reinstallEvery {
			continue
		}
		b.reinstalled = true
		ctl.rlast[h] = now
		ctl.rwg.Add(1)
		go ctl.reinstallHost(h)
	}
}

func (ctl *Controller) reinstallHost(host string) {
	defer ctl.rwg.Done()
	ctx := ctl.rctx
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, reinstallTimeout)
	defer cancel()
	ctl.record(incident.Incident{Kind: "reinstall", Action: "alert", Severity: model.SevHigh, Host: host,
		Detail: "silent: reinstalling over ssh"})
	cfg := &Config{Reinstall: ctl.rcfg}
	if err := Reinstall(ctx, ctl.dir, cfg, host, ctl.rssh, ctl.rbinary); err != nil {
		ctl.record(incident.Incident{Kind: "reinstall", Action: "failed", Severity: model.SevHigh, Host: host, Detail: err.Error()})
		return
	}
	ctl.record(incident.Incident{Kind: "reinstall", Action: "repaired", Severity: model.SevMedium, Host: host,
		Detail: "agent reinstalled over ssh"})
}
