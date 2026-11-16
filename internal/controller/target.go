package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xdr/internal/config"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

// TargetOptions is what `xdr controller add-target` was given.
type TargetOptions struct {
	Host        string
	Scored      []config.Port
	Listeners   []config.Listener // as `xdr listeners` printed them
	Blue, Gray  []string
	Auto        []string
	Recovery    string
	RecoveryKey string // its authorized_keys line
	Kill        bool
	Baseline    []byte // nil: none in the bundle
	Script      []byte // install-target.sh
}

// sshdListener is always a known listener: the way in is never killed.
var sshdListener = config.Listener{Proto: "tcp", Port: 22, Exe: "/usr/sbin/sshd"}

// ParseScored reads "tcp/80,udp/53".
func ParseScored(s string) ([]config.Port, error) {
	if strings.TrimSpace(s) == "" {
		return nil, fmt.Errorf("--scored: no port given (as tcp/80,udp/53)")
	}
	var out []config.Port
	for _, f := range strings.Split(s, ",") {
		proto, port, ok := strings.Cut(strings.TrimSpace(f), "/")
		n, err := strconv.ParseUint(port, 10, 16)
		if !ok || (proto != "tcp" && proto != "udp") || err != nil || n == 0 {
			return nil, fmt.Errorf("--scored: %q is not tcp/PORT or udp/PORT", f)
		}
		p := config.Port{Proto: proto, Port: uint16(n)}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

// ParseListeners reads a --listeners file: the array `xdr listeners`
// prints, or prep-target.sh's facts with it under "listeners".
func ParseListeners(b []byte) ([]config.Listener, error) {
	var out []config.Listener
	if err := json.Unmarshal(b, &out); err == nil {
		return out, nil
	}
	var facts struct {
		Listeners *[]config.Listener `json:"listeners"`
	}
	if err := json.Unmarshal(b, &facts); err != nil || facts.Listeners == nil {
		return nil, fmt.Errorf("not the output of xdr listeners or prep-target.sh")
	}
	return *facts.Listeners, nil
}

type agentFleet struct {
	Endpoints []string `json:"endpoints"`
	Dir       string   `json:"dir"`
}

type agentSSH struct {
	Blue        []string `json:"blue_users"`
	Recovery    string   `json:"recovery,omitempty"`
	RecoveryKey string   `json:"recovery_key,omitempty"`
	Auto        []string `json:"auto"`
}

type agentConfig struct {
	Host      string            `json:"host"`
	Jump      []string          `json:"jump"`
	XDRPorts  []uint16          `json:"xdr_ports"`
	Scored    []config.Port     `json:"scored"`
	Listeners []config.Listener `json:"listeners"`
	GrayUsers []string          `json:"gray_users"`
	Kill      bool              `json:"kill"`
	Fleet     agentFleet        `json:"fleet"`
	SSH       *agentSSH         `json:"ssh,omitempty"`
}

// TargetConfig is the agent.json for o's host of the controller in dir:
// its jump box and fleet endpoint are the controller's listen address. It
// is checked with the agent's own loader.
func TargetConfig(dir string, o TargetOptions) ([]byte, error) {
	if !config.Hostname(o.Host) || o.Host == "root" {
		return nil, fmt.Errorf("--host %q: a lower-case host name is needed", o.Host)
	}
	if len(o.Scored) == 0 {
		return nil, fmt.Errorf("--scored: no port given")
	}
	if (o.Recovery == "") != (o.RecoveryKey == "") {
		return nil, fmt.Errorf("--recovery and --recovery-key go together")
	}
	cfg, err := LoadConfig(filepath.Join(dir, "controller.json"))
	if err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(cfg.Listen)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("controller.json: listen %q: the agents need an IP address", cfg.Listen)
	}
	pn, _ := strconv.ParseUint(port, 10, 16)
	ports := []uint16{7443}
	if !slices.Contains(ports, uint16(pn)) {
		ports = append(ports, uint16(pn))
	}
	// The scored ports are left out, as `xdr listeners --config` does.
	ls := []config.Listener{}
	for _, l := range o.Listeners {
		if !slices.Contains(o.Scored, config.Port{Proto: l.Proto, Port: l.Port}) && !slices.Contains(ls, l) {
			ls = append(ls, l)
		}
	}
	if !slices.Contains(ls, sshdListener) {
		ls = append(ls, sshdListener)
	}
	a := agentConfig{
		Host: o.Host, Jump: []string{addr.String()}, XDRPorts: ports, Scored: o.Scored, Listeners: ls,
		GrayUsers: o.Gray, Kill: o.Kill,
		Fleet: agentFleet{Endpoints: []string{net.JoinHostPort(addr.String(), port)}, Dir: config.DefaultFleetDir},
	}
	if a.GrayUsers == nil {
		a.GrayUsers = []string{}
	}
	if len(o.Blue) > 0 || o.Recovery != "" || len(o.Auto) > 0 {
		a.SSH = &agentSSH{Blue: o.Blue, Recovery: o.Recovery, RecoveryKey: strings.TrimSpace(o.RecoveryKey), Auto: o.Auto}
		if a.SSH.Blue == nil {
			a.SSH.Blue = []string{}
		}
		if a.SSH.Auto == nil {
			a.SSH.Auto = []string{}
		}
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if _, err := config.Parse(b); err != nil {
		return nil, fmt.Errorf("the agent config would not load: %w", err)
	}
	return b, nil
}

// BuildTarget enrols o's host and returns its bundle: a gzipped tar of
// fleet/{ca.pem,host.pem,host-key.pem,rules.pub}, agent.json signed with
// the rule key (agent.json.sig), install-target.sh and, when given, the
// baseline. Nothing is enrolled when the config does not check.
func BuildTarget(dir string, o TargetOptions) ([]byte, error) {
	cfg, err := TargetConfig(dir, o)
	if err != nil {
		return nil, err
	}
	key, err := rules.LoadPrivate(filepath.Join(dir, "rules.key"))
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "xdr-add-target-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	bundle := filepath.Join(tmp, "fleet")
	if err := pki.Enroll(dir, o.Host, bundle); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	now := time.Now().Truncate(time.Second)
	add := func(name string, mode int64, data []byte) error {
		h := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: now, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: "fleet/", Mode: 0o700, ModTime: now, Typeflag: tar.TypeDir, Format: tar.FormatPAX}); err != nil {
		return nil, err
	}
	for _, name := range []string{"ca.pem", "host.pem", "host-key.pem", "rules.pub"} {
		b, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			return nil, err
		}
		if err := add("fleet/"+name, 0o600, b); err != nil {
			return nil, err
		}
	}
	files := []struct {
		name string
		mode int64
		data []byte
	}{
		{"agent.json", 0o600, cfg},
		{"agent.json.sig", 0o644, config.Signature(cfg, key)},
		{"install-target.sh", 0o755, o.Script},
	}
	if o.Baseline != nil {
		files = append(files, struct {
			name string
			mode int64
			data []byte
		}{"baseline.json.gz", 0o600, o.Baseline})
	}
	for _, f := range files {
		if err := add(f.name, f.mode, f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
