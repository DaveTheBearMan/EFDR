package heal

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"xdr/internal/config"
)

var (
	fleetNets = []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("198.51.100.0/24")}
	agentPort = []uint16{22, 7443, 2379}
	scoredSet = []config.Port{{Proto: "tcp", Port: 80}}
)

const realNft = `# Warning: table ip filter is managed by iptables-nft, do not touch!
table inet xdr { # handle 1
	chain input { # handle 1
		type filter hook input priority -10; policy accept;
		ip saddr 192.0.2.7 drop # handle 2
	}
}
table ip nat { # handle 2
	chain POSTROUTING { # handle 1
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 192.0.2.7 drop # handle 3
	}
}
table ip filter { # handle 3
	chain INPUT { # handle 5
		type filter hook input priority filter; policy accept;
		counter packets 5709451 bytes 3095515941 jump ts-input # handle 115
	}
}
table inet bad { # handle 4
	chain input { # handle 1
		type filter hook input priority 0; policy accept;
		ip daddr 192.0.2.7 drop # handle 4
		tcp dport 80 drop # handle 5
		ip saddr 203.0.113.5 accept # handle 6
		tcp dport 22 drop # handle 10
		ip saddr 198.51.100.9 tcp dport 7443 drop # handle 11
		ip saddr 203.0.113.5 comment "drop 192.0.2.7 now" accept # handle 12
		ip saddr 203.0.113.5 counter packets 1 bytes 2 comment "192.0.2.7" drop # handle 13
	}
}
table ip scoredonly { # handle 5
	chain input { # handle 1
		type filter hook input priority 0; policy accept;
		tcp dport 80 drop # handle 7
		tcp dport 9999 drop # handle 8
	}
}
table ip6 rej { # handle 6
	chain output { # handle 1
		type filter hook output priority 0; policy accept;
		tcp dport 2379 counter packets 0 bytes 0 reject # handle 9
	}
}
`

func TestNftBlockers(t *testing.T) {
	// Scored: 80, and the agent's own 22 and 7443: a rule naming any of
	// them is left, even beside a fleet address.
	scored := []config.Port{{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 7443}}
	got := NftBlockers(realNft, fleetNets, agentPort, scored)
	want := []Table{
		{Family: "inet", Name: "bad", Rules: []NftRule{{Chain: "input", Handle: 4}}},
		{Family: "ip6", Name: "rej", Rules: []NftRule{{Chain: "output", Handle: 9}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	// With 22 and 7443 not scored, the rules naming them are blockers.
	got = NftBlockers(realNft, fleetNets, agentPort, scoredSet)
	want[0].Rules = []NftRule{{Chain: "input", Handle: 4}, {Chain: "input", Handle: 10}, {Chain: "input", Handle: 11}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unscored: got %+v want %+v", got, want)
	}
}

func TestIptablesBlockers(t *testing.T) {
	save := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.7/32 -j DROP
-A INPUT -p tcp -m tcp --dport 7443 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 80 -j DROP
-A INPUT -p tcp -m tcp --dport 22 -j DROP
-A INPUT -s 192.0.2.7/32 -p tcp -m tcp --dport 7443 -j DROP
-A INPUT -s 203.0.113.5/32 -j DROP
-A INPUT -p tcp -m comment --comment "a b" -s 198.51.100.9/32 -j DROP
-A DOCKER -s 192.0.2.7/32 -j DROP
-A INPUT -s 192.0.2.7/32 -j ACCEPT
COMMIT
*nat
-A PREROUTING -s 192.0.2.7/32 -j DROP
COMMIT
`
	// 22 and 7443 scored: the rules naming them stay.
	scored := []config.Port{{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 7443}}
	got := IptablesBlockers(save, fleetNets, agentPort, scored)
	want := [][]string{
		{"-t", "filter", "-D", "INPUT", "-s", "192.0.2.7/32", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "comment", "--comment", "a b", "-s", "198.51.100.9/32", "-j", "DROP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	// Only 80 scored: 7443 and 22 rules go too.
	got = IptablesBlockers(save, fleetNets, agentPort, scoredSet)
	want = [][]string{
		{"-t", "filter", "-D", "INPUT", "-s", "192.0.2.7/32", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "7443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-s", "192.0.2.7/32", "-p", "tcp", "-m", "tcp", "--dport", "7443", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "comment", "--comment", "a b", "-s", "198.51.100.9/32", "-j", "DROP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unscored: got %q want %q", got, want)
	}
}

func TestRouteBlockers(t *testing.T) {
	rules := "0:\tfrom all lookup local\n100:\tfrom all to 192.0.2.7 prohibit\n32766:\tfrom all lookup main\n"
	routes := "default via 192.0.2.1 dev eth0\nblackhole 192.0.2.7\nunreachable 198.51.100.0/24\nblackhole 203.0.113.0/24\n192.0.2.0/24 dev eth0 proto kernel\n"
	got := RouteBlockers(rules, routes, fleetNets)
	want := []string{
		"ip rule del pref 100 from all to 192.0.2.7 prohibit",
		"ip route del blackhole 192.0.2.7",
		"ip route del unreachable 198.51.100.0/24",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDenyLines(t *testing.T) {
	deny := "# comment 192.0.2.7\nALL: 192.0.2.7\nsshd: 198.51.100.\nALL: 203.0.113.5\n\nsshd:192.0.2.7\n"
	got := DenyLines(deny, fleetNets)
	want := []string{"ALL: 192.0.2.7", "sshd: 198.51.100.", "sshd:192.0.2.7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	if strings.Contains(strings.Join(got, "|"), "203.0.113") {
		t.Fatal("harmless line returned")
	}
}

func TestRouteBlockers_IPv6(t *testing.T) {
	fleet6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	rules := "0:\tfrom all lookup local\n100:\tfrom all to 2001:db8::7 prohibit\n"
	routes := "blackhole 2001:db8::7 dev lo metric 1024\nblackhole 2001:4860::/32\n"
	got := RouteBlockers(rules, routes, fleet6)
	want := []string{
		"ip rule del pref 100 from all to 2001:db8::7 prohibit",
		"ip route del blackhole 2001:db8::7 dev lo metric 1024",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
