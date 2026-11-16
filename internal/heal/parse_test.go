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

func TestNftBlockers(t *testing.T) {
	rs := `table inet xdr {
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr 192.0.2.7 drop # handle 2
	}
}
table ip nat {
	chain POSTROUTING {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 192.0.2.7 drop # handle 3
	}
}
table inet bad {
	chain input {
		type filter hook input priority 0; policy accept;
		ip daddr 192.0.2.7 drop # handle 4
		tcp dport 80 drop # handle 5
		ip saddr 203.0.113.5 accept # handle 6
	}
}
table ip scoredonly {
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 80 drop # handle 7
		tcp dport 9999 drop # handle 8
	}
}
table ip6 rej {
	chain output {
		type filter hook output priority 0; policy accept;
		tcp dport 2379 counter packets 0 bytes 0 reject # handle 9
	}
}
`
	got := NftBlockers(rs, fleetNets, agentPort, scoredSet)
	want := []Table{
		{Family: "inet", Name: "bad", Rules: []NftRule{{Chain: "input", Handle: 4}}},
		{Family: "ip6", Name: "rej", Rules: []NftRule{{Chain: "output", Handle: 9}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestIptablesBlockers(t *testing.T) {
	save := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.7/32 -j DROP
-A INPUT -p tcp -m tcp --dport 7443 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -m tcp --dport 80 -j DROP
-A INPUT -s 203.0.113.5/32 -j DROP
-A INPUT -p tcp -m comment --comment "a b" -s 198.51.100.9/32 -j DROP
-A DOCKER -s 192.0.2.7/32 -j DROP
-A INPUT -s 192.0.2.7/32 -j ACCEPT
COMMIT
*nat
-A PREROUTING -s 192.0.2.7/32 -j DROP
COMMIT
`
	got := IptablesBlockers(save, fleetNets, agentPort, scoredSet)
	want := [][]string{
		{"-t", "filter", "-D", "INPUT", "-s", "192.0.2.7/32", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", "7443", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "comment", "--comment", "a b", "-s", "198.51.100.9/32", "-j", "DROP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRouteBlockers(t *testing.T) {
	rules := "0:\tfrom all lookup local\n100:\tfrom all to 192.0.2.7 prohibit\n32766:\tfrom all lookup main\n"
	routes := "default via 10.0.0.1 dev eth0\nblackhole 192.0.2.7\nunreachable 198.51.100.0/24\nblackhole 203.0.113.0/24\n10.0.0.0/24 dev eth0 proto kernel\n"
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
