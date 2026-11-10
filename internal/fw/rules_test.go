package fw

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"xdr/internal/config"
)

var (
	now      = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	jump     = netip.MustParseAddr("192.0.2.7")
	peer     = netip.MustParseAddr("192.0.2.4")
	box      = netip.MustParseAddr("192.0.2.5")
	db       = netip.MustParseAddr("192.0.2.3")
	resolver = netip.MustParseAddr("192.0.2.1")
	stranger = netip.MustParseAddr("203.0.113.9")
	gray     = netip.MustParseAddr("198.51.100.20")
)

func nets(ss ...string) []config.Net {
	var out []config.Net
	for _, s := range ss {
		var n config.Net
		if err := n.UnmarshalText([]byte(s)); err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

func fixture() *config.Config {
	return &config.Config{
		Jump: nets("192.0.2.7"), Peers: nets("192.0.2.4"), SSHFrom: nets("198.51.100.0/24"),
		SSHPort: 22, XDRPorts: []uint16{7443}, DHCP: true,
		Scored:   []config.Port{{Proto: "tcp", Port: 80}},
		AllowOut: []config.Dest{{To: nets("192.0.2.3")[0], Proto: "tcp", Port: 3306}},
		DNS:      config.DNS{Resolver: resolver},
	}
}

func tcp(hook int, src, dst netip.Addr, sport, dport uint16) Packet {
	return Packet{Hook: hook, State: StateNew, Proto: unix.IPPROTO_TCP, Src: src, Dst: dst, SPort: sport, DPort: dport, ICMPType: -1}
}

func udp(hook int, src, dst netip.Addr, sport, dport uint16) Packet {
	p := tcp(hook, src, dst, sport, dport)
	p.Proto = unix.IPPROTO_UDP
	return p
}

func echo(hook int, src, dst netip.Addr) Packet {
	return Packet{Hook: hook, State: StateNew, Proto: unix.IPPROTO_ICMP, Src: src, Dst: dst, ICMPType: 8}
}

type vcase struct {
	name string
	p    Packet
	want Action
}

func check(t *testing.T, rs Ruleset, cases []vcase) {
	t.Helper()
	for _, c := range cases {
		if got := rs.Verdict(c.p); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestVerdict_Inbound(t *testing.T) {
	check(t, Build(fixture(), now), []vcase{
		{"scored from stranger", tcp(HookInput, stranger, box, 50000, 80), Accept},
		{"unknown port", tcp(HookInput, stranger, box, 50000, 4444), Drop},
		{"ssh from jump", tcp(HookInput, jump, box, 50000, 22), Accept},
		{"ssh from gray subnet", tcp(HookInput, gray, box, 50000, 22), Accept},
		{"ssh from stranger", tcp(HookInput, stranger, box, 50000, 22), Drop},
		{"ssh from peer", tcp(HookInput, peer, box, 50000, 22), Drop},
		{"xdr from peer", tcp(HookInput, peer, box, 50000, 7443), Accept},
		{"xdr from jump", tcp(HookInput, jump, box, 50000, 7443), Accept},
		{"xdr from stranger", tcp(HookInput, stranger, box, 50000, 7443), Drop},
		{"udp to scored tcp port", udp(HookInput, stranger, box, 50000, 80), Drop},
		{"echo request in", echo(HookInput, stranger, box), Accept},
		{"dhcp reply", udp(HookInput, resolver, box, 67, 68), Accept},
	})
}

func TestVerdict_Outbound(t *testing.T) {
	lo := tcp(HookOutput, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), 50000, 9000)
	lo.Loopback = true
	check(t, Build(fixture(), now), []vcase{
		{"to stranger", tcp(HookOutput, box, stranger, 50000, 443), Drop},
		{"xdr to peer", tcp(HookOutput, box, peer, 50000, 7443), Accept},
		{"xdr to jump", tcp(HookOutput, box, jump, 50000, 7443), Accept},
		{"jump other port", tcp(HookOutput, box, jump, 50000, 4444), Drop},
		{"allow_out", tcp(HookOutput, box, db, 50000, 3306), Accept},
		{"allow_out host, other port", tcp(HookOutput, box, db, 50000, 22), Drop},
		{"echo request out", echo(HookOutput, box, stranger), Drop},
		{"dhcp request", udp(HookOutput, box, netip.MustParseAddr("255.255.255.255"), 68, 67), Accept},
		{"loopback", lo, Accept},
	})
	c := fixture()
	c.DHCP = false
	check(t, Build(c, now), []vcase{
		{"dhcp off, request", udp(HookOutput, box, resolver, 68, 67), Drop},
		{"dhcp off, reply", udp(HookInput, resolver, box, 67, 68), Drop},
	})
}

func TestVerdict_EstablishedOriginalDirectionNeedsAllow(t *testing.T) {
	est := func(p Packet, reply bool) Packet { p.State, p.Reply = StateEstablished, reply; return p }
	inv := tcp(HookInput, stranger, box, 50000, 80)
	inv.State = StateInvalid
	check(t, Build(fixture(), now), []vcase{
		{"reverse shell, our packets", est(tcp(HookOutput, box, stranger, 50000, 9999), false), Drop},
		// Data from the far end would still reach the shell's stdin.
		{"reverse shell, their replies", est(tcp(HookInput, stranger, box, 9999, 50000), true), Drop},
		{"reverse shell from a scored source port", est(tcp(HookOutput, box, stranger, 80, 9999), false), Drop},
		{"its replies", est(tcp(HookInput, stranger, box, 9999, 80), true), Drop},
		{"reply from a stranger on the xdr port", est(tcp(HookInput, stranger, box, 7443, 50000), true), Drop},
		{"ssh reply to jump", est(tcp(HookOutput, box, jump, 22, 50000), true), Accept},
		{"ssh reply to stranger", est(tcp(HookOutput, box, stranger, 22, 50000), true), Drop},
		{"xdr reply to peer", est(tcp(HookOutput, box, peer, 7443, 50000), true), Accept},
		{"allow_out reply", est(tcp(HookInput, db, box, 3306, 50000), true), Accept},
		{"echo reply out", est(Packet{Hook: HookOutput, Proto: unix.IPPROTO_ICMP, Src: box, Dst: stranger, ICMPType: 0}, true), Accept},
		{"echo reply in", est(Packet{Hook: HookInput, Proto: unix.IPPROTO_ICMP, Src: stranger, Dst: box, ICMPType: 0}, true), Drop},
		{"bind shell, their packets", est(tcp(HookInput, stranger, box, 50000, 4444), false), Drop},
		{"xdr reply from peer", est(tcp(HookInput, peer, box, 7443, 50000), true), Accept},
		{"scored reply out", est(tcp(HookOutput, box, stranger, 80, 50000), true), Accept},
		{"scored original in", est(tcp(HookInput, stranger, box, 50000, 80), false), Accept},
		{"invalid to scored", inv, Drop},
	})
}

func TestVerdict_DNS(t *testing.T) {
	q := func(dst netip.Addr, mark uint32) Packet {
		p := udp(HookOutput, box, dst, 50000, 53)
		p.Mark = mark
		return p
	}
	off := fixture()
	on := fixture()
	on.DNS.Enabled = true
	expired := fixture()
	expired.DNS.Enabled, expired.DNS.Expires = true, now.Add(-time.Second)
	answer := func(src netip.Addr) Packet {
		p := udp(HookInput, src, box, 53, 50000)
		p.State, p.Reply = StateEstablished, true
		return p
	}
	check(t, Build(off, now), []vcase{{"switch off", q(resolver, DNSMark), Drop}, {"answer, switch off", answer(resolver), Drop}})
	check(t, Build(expired, now), []vcase{{"switch expired", q(resolver, DNSMark), Drop}})
	check(t, Build(on, now), []vcase{
		{"agent to resolver", q(resolver, DNSMark), Accept},
		{"answer", answer(resolver), Accept},
		{"answer from another server", answer(stranger), Drop},
		{"unmarked to resolver", q(resolver, 0), Drop},
		{"marked to another server", q(netip.MustParseAddr("203.0.113.53"), DNSMark), Drop},
		{"tcp 53", tcp(HookOutput, box, resolver, 50000, 53), Drop},
		{"tcp 853", tcp(HookOutput, box, stranger, 50000, 853), Drop},
	})
}

func TestVerdict_Forward(t *testing.T) {
	ctr := netip.MustParseAddr("172.17.0.2")
	dnat := func(orig uint16) Packet {
		p := tcp(HookForward, stranger, ctr, 50000, 80)
		p.DNAT, p.OrigDPort = true, orig
		return p
	}
	est := func(p Packet) Packet { p.State, p.Reply = StateEstablished, true; return p }
	reply := est(tcp(HookForward, ctr, stranger, 80, 50000))
	reply.DNAT, reply.OrigDPort = true, 80
	check(t, Build(fixture(), now), []vcase{
		{"published scored port", dnat(80), Accept},
		{"published other port", dnat(8081), Drop},
		{"not dnat", tcp(HookForward, stranger, ctr, 50000, 80), Drop},
		{"container egress", tcp(HookForward, ctr, stranger, 50000, 443), Drop},
		{"container to allow_out", tcp(HookForward, ctr, db, 50000, 3306), Accept},
		{"published scored port, reply", reply, Accept},
		{"reply of a connection that was never allowed", est(tcp(HookForward, ctr, stranger, 80, 50000)), Drop},
		{"container reverse shell, their replies", est(tcp(HookForward, stranger, ctr, 443, 50000)), Drop},
		{"allow_out reply", est(tcp(HookForward, db, ctr, 3306, 50000)), Accept},
	})
}

func TestVerdict_IPv6(t *testing.T) {
	c := fixture()
	c.SSHFrom = nets("2001:db8::/32")
	box6 := netip.MustParseAddr("2001:db8::5")
	ns := Packet{Hook: HookInput, State: StateNew, Proto: unix.IPPROTO_ICMPV6, Src: box6, Dst: box6, ICMPType: 135}
	mapped := tcp(HookInput, netip.MustParseAddr("::ffff:192.0.2.7"), box, 50000, 22)
	check(t, Build(c, now), []vcase{
		{"ssh v6 allowed", tcp(HookInput, netip.MustParseAddr("2001:db8::9"), box6, 50000, 22), Accept},
		{"ssh v6 stranger", tcp(HookInput, netip.MustParseAddr("2001:dead::9"), box6, 50000, 22), Drop},
		{"scored v6", tcp(HookInput, netip.MustParseAddr("2001:dead::9"), box6, 50000, 80), Accept},
		{"neighbour solicit", ns, Accept},
		{"v4-mapped jump", mapped, Accept},
	})
}

func TestString(t *testing.T) {
	s := Build(fixture(), now).String()
	for _, want := range []string{"chain input", "chain output", "chain forward", " ip saddr 192.0.2.7 tcp dport 22 accept", "ct direction original ip saddr 198.51.100.0/24 tcp dport 22 accept",
		"ct direction reply ct state established,related tcp sport 80 accept",
		" ip saddr 192.0.2.4 tcp sport 7443 accept", "ip daddr 192.0.2.3 tcp dport 3306 accept", "ct original proto-dst 80 accept"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "established,related accept") {
		t.Error("a reply rule that accepts any connection")
	}
	if strings.Contains(s, "dport 53") {
		t.Error("DNS rule present with the switch off")
	}
}

// A connection open when conntrack starts (a host that was tracking
// nothing before our table) is picked up from whichever packet comes
// first, and that packet's direction becomes "original". The operator's
// session from the jump box, and the agents' own, must survive the box
// speaking first; nothing else gets that latitude.
func TestVerdict_JumpSessionPickedUpMidStream(t *testing.T) {
	picked := func(p Packet, reply bool) Packet {
		p.Reply = reply
		if reply {
			p.State = StateEstablished
		}
		return p
	}
	check(t, Build(fixture(), now), []vcase{
		{"box speaks first to jump", picked(tcp(HookOutput, box, jump, 22, 50000), false), Accept},
		{"then jump's packets", picked(tcp(HookInput, jump, box, 50000, 22), true), Accept},
		{"xdr: box speaks first to peer", picked(tcp(HookOutput, box, peer, 7443, 50000), false), Accept},
		{"then the peer's packets", picked(tcp(HookInput, peer, box, 50000, 7443), true), Accept},
		{"ssh from the gray subnet stays strict", picked(tcp(HookOutput, box, gray, 22, 50000), false), Drop},
		{"so do its packets", picked(tcp(HookInput, gray, box, 50000, 22), true), Drop},
		{"scored stays strict", picked(tcp(HookOutput, box, stranger, 80, 50000), false), Drop},
		{"from source port 22 to a stranger", picked(tcp(HookOutput, box, stranger, 22, 50000), false), Drop},
		{"jump's ssh port is not jump's any port", picked(tcp(HookOutput, box, jump, 4444, 50000), false), Drop},
	})
}
