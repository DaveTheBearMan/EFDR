package heal

import (
	"net/netip"
	"reflect"
	"testing"

	"xdr/internal/config"
)

// setsNft is real `nft -a list ruleset` output (nft 1.x, from a throwaway
// network namespace): named sets, one wrapped over several lines, a
// timeout set, a v4-mapped v6 address and a comment naming a fleet
// address.
const setsNft = `
table inet bad { # handle 1
	set blocklist { # handle 2
		type ipv4_addr
		elements = { 192.0.2.7, 198.51.100.9,
			     198.51.100.10, 198.51.100.11,
			     198.51.100.12, 198.51.100.13,
			     198.51.100.14, 198.51.100.15,
			     198.51.100.16, 198.51.100.17,
			     198.51.100.18 }
	}

	set mixed { # handle 3
		type ipv4_addr
		elements = { 192.0.2.7, 203.0.113.9 }
	}

	set ports { # handle 4
		type inet_service
		elements = { 22, 80 }
	}

	set agentports { # handle 5
		type inet_service
		elements = { 2379, 7443 }
	}

	set v6 { # handle 6
		type ipv6_addr
		elements = { ::ffff:192.0.2.7 }
	}

	set tset { # handle 7
		type ipv4_addr
		flags timeout
		elements = { 192.0.2.7 timeout 1h expires 59m59s992ms }
	}

	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		ip saddr @blocklist drop # handle 8
		ip saddr @mixed drop # handle 9
		tcp dport @ports drop # handle 10
		tcp dport @agentports drop # handle 11
		ip6 saddr @v6 drop # handle 12
		ip6 saddr ::ffff:192.0.2.7 drop # handle 13
		ip saddr @tset drop # handle 14
		ip saddr 203.0.113.5 accept comment "say 192.0.2.7 drop" # handle 15
	}
}
`

func TestNftBlockers_Sets(t *testing.T) {
	got := NftBlockers(setsNft, fleetNets, agentPort, scoredSet)
	want := []Table{{Family: "inet", Name: "bad", Rules: []NftRule{
		{Chain: "input", Handle: 8},  // @blocklist: all fleet, wrapped over lines
		{Chain: "input", Handle: 11}, // @agentports: 2379 and 7443 only
		{Chain: "input", Handle: 12}, // @v6: ::ffff:192.0.2.7
		{Chain: "input", Handle: 13}, // ::ffff:192.0.2.7
		{Chain: "input", Handle: 14}, // @tset: an element with a timeout
	}}}
	// Left: @mixed holds 203.0.113.9; @ports holds the scored 80; 15 accepts.
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// A set named but not listed is not judged a blocker.
	if got := NftBlockers("table ip x { # handle 1\n\tchain c { # handle 1\n\t\ttype filter hook input priority 0; policy accept;\n\t\tip saddr @nowhere drop # handle 2\n\t}\n}\n", fleetNets, agentPort, scoredSet); len(got) != 0 {
		t.Fatalf("unknown set judged: %+v", got)
	}
	// A set is the table's own: another table's set of the same name does not count.
	other := "table ip a { # handle 1\n\tset s { # handle 2\n\t\ttype ipv4_addr\n\t\telements = { 192.0.2.7 }\n\t}\n}\n" +
		"table ip b { # handle 2\n\tset s { # handle 1\n\t\ttype ipv4_addr\n\t\telements = { 203.0.113.9 }\n\t}\n\n\tchain c { # handle 2\n\t\ttype filter hook input priority 0; policy accept;\n\t\tip saddr @s drop # handle 3\n\t}\n}\n"
	if got := NftBlockers(other, fleetNets, agentPort, scoredSet); len(got) != 0 {
		t.Fatalf("another table's set judged: %+v", got)
	}
}

func TestNftBlockers_EscapedQuoteInComment(t *testing.T) {
	// The comment holds an escaped quote: the strip must not end there and
	// read the comment's tail as matches.
	rs := "table ip x { # handle 1\n\tchain c { # handle 1\n\t\ttype filter hook input priority 0; policy accept;\n" +
		"\t\tip saddr 203.0.113.5 counter comment \"x\\\" ip saddr 192.0.2.7 \\\"y\" drop # handle 2\n" +
		"\t\tip saddr 192.0.2.7 comment \"a \\\"quoted\\\" word\" drop # handle 3\n\t}\n}\n"
	got := NftBlockers(rs, fleetNets, agentPort, scoredSet)
	want := []Table{{Family: "ip", Name: "x", Rules: []NftRule{{Chain: "c", Handle: 3}}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestParsePrefix_Unmaps(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:192.0.2.7":        "192.0.2.7/32",
		"::ffff:192.0.2.0/120":    "192.0.2.0/24",
		"::ffff:198.51.100.9/128": "198.51.100.9/32",
		"2001:db8::7":             "2001:db8::7/128",
	} {
		p, ok := parsePrefix(in)
		if !ok || p != netip.MustParsePrefix(want) {
			t.Errorf("parsePrefix(%q) = %v %v, want %s", in, p, ok, want)
		}
	}
	// Through the other parsers too.
	if got := IptablesBlockers("*filter\n-A INPUT -s ::ffff:192.0.2.7/128 -j DROP\nCOMMIT\n", fleetNets, agentPort, []config.Port{}); len(got) != 1 {
		t.Errorf("ip6tables mapped address: %q", got)
	}
	if got := DenyLines("ALL: [::ffff:192.0.2.7]\n", fleetNets); len(got) != 1 {
		t.Errorf("hosts.deny mapped address: %q", got)
	}
}
