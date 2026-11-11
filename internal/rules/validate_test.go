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
