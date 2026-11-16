package heal

import (
	"net/netip"
	"reflect"
	"testing"

	"xdr/internal/config"
)

func nftOne(table, chainType, chain, rule string) string {
	return "table " + table + " { # handle 9\n\tchain " + chain + " { # handle 1\n\t\ttype " + chainType +
		" hook input priority 0; policy accept;\n\t\t" + rule + " # handle 42\n\t}\n}\n"
}

// Each rule here must be left: it is not plainly a blocker of the fleet or
// an agent port, or it would take others (or a scored service) with it.
func TestNftBlockers_LeavesWhatIsNotPlainlyABlocker(t *testing.T) {
	scored := []config.Port{{Proto: "tcp", Port: 80}}
	for name, rule := range map[string]string{
		"negated address":        "ip saddr != 192.0.2.7 drop",
		"negated port":           "tcp dport != 7443 drop",
		"wider than the fleet":   "ip saddr 192.0.0.0/8 drop",
		"set with others":        "ip saddr { 192.0.2.7, 203.0.113.5 } drop",
		"range with scored":      "tcp dport 1-1024 drop",
		"set with scored":        "tcp dport { 22, 23, 80 } drop",
		"range with agent port":  "tcp dport 7000-8000 drop",
		"set agent and others":   "tcp dport { 7443, 9999 } drop",
		"fleet and scored set":   "ip saddr 192.0.2.7 tcp dport { 80, 443 } drop",
		"fleet and scored range": "ip saddr 192.0.2.7 tcp dport 1-1024 drop",
		"concatenation":          "ip saddr . tcp dport { 192.0.2.7 . 7443 } drop",
	} {
		if got := NftBlockers(nftOne("inet bad", "filter", "input", rule), fleetNets, agentPort, scored); len(got) != 0 {
			t.Errorf("%s: %q removed: %+v", name, rule, got)
		}
	}
}

func TestNftBlockers_StillRemovesPlainBlockers(t *testing.T) {
	scored := []config.Port{{Proto: "tcp", Port: 80}}
	for name, rule := range map[string]string{
		"fleet address":          "ip saddr 192.0.2.7 drop",
		"inside a fleet net":     "ip saddr 198.51.100.128/25 drop",
		"fleet set":              "ip saddr { 192.0.2.7, 198.51.100.9 } drop",
		"fleet to the box":       "ip saddr 192.0.2.7 ip daddr 203.0.113.9 drop",
		"agent port":             "tcp dport 7443 drop",
		"agent port set":         "tcp dport { 7443, 2379 } drop",
		"fleet, negated another": "ip saddr 192.0.2.7 ip daddr != 203.0.113.9 drop",
	} {
		want := []Table{{Family: "inet", Name: "bad", Rules: []NftRule{{Chain: "input", Handle: 42}}}}
		if got := NftBlockers(nftOne("inet bad", "filter", "input", rule), fleetNets, agentPort, scored); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q: %+v", name, rule, got)
		}
	}
}

// Only the agent's own table is skipped by name; a table called nat (or
// docker, kube, cali) is judged in its filter chains; Docker's and the
// like's chains stay skipped by their names.
func TestNftBlockers_TablesAndChains(t *testing.T) {
	rule := "ip saddr 192.0.2.7 drop"
	for _, c := range []struct {
		table, typ, chain string
		removed           bool
	}{
		{"inet xdr", "filter", "input", false},
		{"ip xdr", "filter", "input", true},
		{"ip nat", "filter", "input", true},
		{"ip nat", "nat", "prerouting", false},
		{"ip docker-bad", "filter", "input", true},
		{"ip kube", "filter", "input", true},
		{"ip calico", "filter", "input", true},
		{"ip filter", "filter", "DOCKER-USER", false},
		{"ip filter", "filter", "KUBE-FIREWALL", false},
		{"ip filter", "filter", "cali-INPUT", false},
		{"ip filter", "filter", "CNI-FORWARD", false},
	} {
		got := NftBlockers(nftOne(c.table, c.typ, c.chain, rule), fleetNets, agentPort, scoredSet)
		if (len(got) == 1) != c.removed {
			t.Errorf("%s/%s (%s): got %+v", c.table, c.chain, c.typ, got)
		}
	}
}

func TestIptablesBlockers_LeavesWhatIsNotPlainlyABlocker(t *testing.T) {
	save := `*filter
-A INPUT ! -s 192.0.2.7/32 -j DROP
-A INPUT -s 192.0.0.0/8 -j DROP
-A INPUT -s 192.0.2.7/32,203.0.113.5/32 -j DROP
-A INPUT -p tcp -m multiport --dports 22,23,80 -j DROP
-A INPUT -p tcp -m tcp --dport 1:1024 -j DROP
-A INPUT -p tcp -m tcp ! --dport 7443 -j DROP
-A INPUT -p tcp -m multiport --dports 7443,9999 -j DROP
-A cali-INPUT -s 192.0.2.7/32 -j DROP
-A INPUT -s 192.0.2.7/32,198.51.100.9/32 -j DROP
-A INPUT -p tcp -m multiport --dports 7443,2379 -j DROP
COMMIT
`
	got := IptablesBlockers(save, fleetNets, agentPort, scoredSet)
	want := [][]string{
		{"-t", "filter", "-D", "INPUT", "-s", "192.0.2.7/32,198.51.100.9/32", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "-m", "multiport", "--dports", "7443,2379", "-j", "DROP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRouteBlockers_WiderThanTheFleetLeft(t *testing.T) {
	got := RouteBlockers("100:\tfrom all to 192.0.0.0/8 prohibit\n", "blackhole 192.0.0.0/8\nblackhole 0.0.0.0/0\n", fleetNets)
	if len(got) != 0 {
		t.Fatalf("%q", got)
	}
}

func TestDenyLines_ExceptAndMixedLeft(t *testing.T) {
	deny := "ALL: ALL EXCEPT 192.0.2.7\nsshd: 192.0.2.7, 203.0.113.5\nALL: 192.\nALL: 192.0.2.7 198.51.100.9\n"
	got := DenyLines(deny, []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("198.51.100.0/24")})
	if want := []string{"ALL: 192.0.2.7 198.51.100.9"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}
