// Package config is the agent's deployment configuration: everything that
// differs between one box and the next. Nothing here is compiled in.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"xdr/internal/collect"
)

// Net is an address or a CIDR block.
type Net struct{ netip.Prefix }

// UnmarshalText accepts "192.0.2.7" (a single host) or "192.0.2.0/24".
func (n *Net) UnmarshalText(b []byte) error {
	s := string(b)
	if p, err := netip.ParsePrefix(s); err == nil {
		n.Prefix = p.Masked()
		return nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("bad address or CIDR %q", s)
	}
	a = a.Unmap()
	n.Prefix = netip.PrefixFrom(a, a.BitLen())
	return nil
}

// Port is a transport port.
type Port struct {
	Proto string `json:"proto"` // "tcp" or "udp"
	Port  uint16 `json:"port"`
}

// Dest is an outbound destination a scored service needs.
type Dest struct {
	To    Net    `json:"to"`
	Proto string `json:"proto"`
	Port  uint16 `json:"port"`
}

// Listener is a listening socket known to be legitimate.
type Listener struct {
	Proto string `json:"proto"` // tcp, udp, or packet/raw (holders of such sockets; no port)
	Port  uint16 `json:"port,omitempty"`
	Exe   string `json:"exe"`
}

// DNS configures name resolution, which is off unless switched on.
type DNS struct {
	Resolver netip.Addr            `json:"resolver"` // the team resolver
	Enabled  bool                  `json:"enabled"`  // the switch
	Expires  time.Time             `json:"expires"`  // zero: no expiry
	Allow    []string              `json:"allow"`    // names the stub may forward
	Hosts    map[string]netip.Addr `json:"hosts"`    // written to /etc/hosts
	Listen   string                `json:"listen"`   // where the stub listens
}

// Config is one box's deployment configuration.
type Config struct {
	Host       string     `json:"host"`
	Jump       []Net      `json:"jump"`        // SSH and XDR are allowed from here
	Peers      []Net      `json:"peers"`       // the other agents
	SSHFrom    []Net      `json:"ssh_from"`    // further SSH sources
	SSHPort    uint16     `json:"ssh_port"`    //
	XDRPorts   []uint16   `json:"xdr_ports"`   //
	Scored     []Port     `json:"scored"`      // open to anyone
	AllowOut   []Dest     `json:"allow_out"`   // outbound a scored service needs
	GuardExes  []string   `json:"guard_exes"`  // scored-service binaries, never killed
	Listeners  []Listener `json:"listeners"`   // known listeners
	GrayUsers  []string   `json:"gray_users"`  // accounts that are never touched
	DHCP       bool       `json:"dhcp"`        //
	DHCPServer []Net      `json:"dhcp_server"` // where renewals and replies may go and come from
	Kill       bool       `json:"kill"`        // false: log would-kill instead
	DNS        DNS        `json:"dns"`
	Fleet      *Fleet     `json:"fleet"`       // nil: a standalone agent
	RulesCache string     `json:"rules_cache"` // the last verified rule set
}

// Fleet is how the agent reaches the controller's etcd.
type Fleet struct {
	Endpoints []string `json:"endpoints"` // address:port, each in jump
	Dir       string   `json:"dir"`       // ca.pem, host.pem, host-key.pem, rules.pub
}

// Load reads and validates the config at path. A field it does not know is
// an error: a misspelt key must not silently fall back to a default.
func Load(path string) (*Config, error) {
	data, err := collect.ReadFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	c := &Config{SSHPort: 22, XDRPorts: []uint16{7443}, DHCP: true, Kill: true, DNS: DNS{Listen: "127.0.0.1:53"},
		RulesCache: "/var/lib/xdr/rules.json"}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, err
	}
	if c.Fleet != nil && c.Fleet.Dir == "" {
		c.Fleet.Dir = "/etc/xdr/fleet"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// DNSOn reports whether the DNS switch is on at now.
func (c *Config) DNSOn(now time.Time) bool {
	return c.DNS.Enabled && (c.DNS.Expires.IsZero() || now.Before(c.DNS.Expires))
}

// Validate refuses a config that would lock the operator out or that the
// agent could not act on exactly.
func (c *Config) Validate() error {
	if len(c.Jump) == 0 {
		return fmt.Errorf("jump: no address given; applying the firewall would lock you out")
	}
	for name, nets := range map[string][]Net{"jump": c.Jump, "peers": c.Peers, "ssh_from": c.SSHFrom} {
		for _, n := range nets {
			if !n.IsValid() {
				return fmt.Errorf("%s: empty address", name)
			}
		}
	}
	if c.Host != "" && !Hostname(c.Host) {
		return fmt.Errorf("host: %q is not a host name", c.Host)
	}
	if c.SSHPort == 0 {
		return fmt.Errorf("ssh_port: 0")
	}
	if len(c.XDRPorts) == 0 {
		return fmt.Errorf("xdr_ports: empty")
	}
	for _, p := range c.XDRPorts {
		if p == 0 {
			return fmt.Errorf("xdr_ports: 0")
		}
	}
	for _, p := range c.Scored {
		if err := transport("scored", p.Proto, p.Port); err != nil {
			return err
		}
	}
	for _, d := range c.AllowOut {
		if err := transport("allow_out", d.Proto, d.Port); err != nil {
			return err
		}
		if !d.To.IsValid() {
			return fmt.Errorf("allow_out: no \"to\" address")
		}
	}
	for _, l := range c.Listeners {
		switch {
		case l.Proto == "packet" || l.Proto == "raw":
			if l.Port != 0 {
				return fmt.Errorf("listeners: a %s socket has no port", l.Proto)
			}
		default:
			if err := transport("listeners", l.Proto, l.Port); err != nil {
				return err
			}
		}
		if !filepath.IsAbs(l.Exe) {
			return fmt.Errorf("listeners: exe %q is not an absolute path", l.Exe)
		}
	}
	for _, e := range c.GuardExes {
		if !filepath.IsAbs(e) {
			return fmt.Errorf("guard_exes: %q is not an absolute path", e)
		}
	}
	for _, u := range c.GrayUsers {
		if u == "" || strings.ContainsAny(u, ": \t\n") {
			return fmt.Errorf("gray_users: %q is not a user name", u)
		}
	}
	if c.DNS.Enabled && !c.DNS.Resolver.IsValid() {
		return fmt.Errorf("dns: enabled without a resolver")
	}
	if _, err := netip.ParseAddrPort(c.DNS.Listen); err != nil {
		return fmt.Errorf("dns.listen: %q is not address:port", c.DNS.Listen)
	}
	for _, n := range c.DNS.Allow {
		if !Hostname(n) {
			return fmt.Errorf("dns.allow: %q is not a lower-case host name", n)
		}
	}
	for n, a := range c.DNS.Hosts {
		if !Hostname(n) || !a.IsValid() {
			return fmt.Errorf("dns.hosts: bad entry %q", n)
		}
	}
	if c.Fleet != nil {
		return c.validateFleet()
	}
	return nil
}

// validateFleet refuses a fleet section the firewall would not let
// through.
func (c *Config) validateFleet() error {
	if c.Host == "" {
		return fmt.Errorf("fleet: host is required; it is the name in the host's certificate")
	}
	if len(c.Fleet.Endpoints) == 0 {
		return fmt.Errorf("fleet.endpoints: empty")
	}
	for _, e := range c.Fleet.Endpoints {
		ap, err := netip.ParseAddrPort(e)
		if err != nil {
			return fmt.Errorf("fleet.endpoints: %q is not address:port", e)
		}
		if !slices.ContainsFunc(c.Jump, func(n Net) bool { return n.Contains(ap.Addr().Unmap()) }) {
			return fmt.Errorf("fleet.endpoints: %s is not in jump", e)
		}
		if !slices.Contains(c.XDRPorts, ap.Port()) {
			return fmt.Errorf("fleet.endpoints: port %d is not in xdr_ports", ap.Port())
		}
	}
	return nil
}

// Protected is every address the box depends on: no rule may name one.
func (c *Config) Protected() []netip.Prefix {
	var out []netip.Prefix
	for _, nets := range [][]Net{c.Jump, c.Peers, c.SSHFrom} {
		for _, n := range nets {
			out = append(out, n.Prefix)
		}
	}
	for _, d := range c.AllowOut {
		out = append(out, d.To.Prefix)
	}
	if a := c.DNS.Resolver; a.IsValid() {
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	for _, n := range c.DHCPServer {
		out = append(out, n.Prefix)
	}
	return out
}

func transport(field, proto string, port uint16) error {
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("%s: proto %q is not tcp or udp", field, proto)
	}
	if port == 0 {
		return fmt.Errorf("%s: port 0", field)
	}
	return nil
}

// Hostname reports whether s is a lower-case DNS name with no trailing dot.
func Hostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
