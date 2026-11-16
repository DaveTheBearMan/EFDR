package fw

import (
	"net/netip"
	"slices"
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
		SSHPort: 22, XDRPorts: []uint16{7443},
		Scored: []config.Port{{Proto: "tcp", Port: 80}},
		DNS:    config.DNS{Resolver: resolver},
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

func blk(addr netip.Addr, proto string, port uint16) Block {
	return Block{Addr: addr, Proto: proto, Port: port}
}

func TestBuild_PolicyAccept(t *testing.T) {
	rs := Build(fixture(), nil, now)
	if rs.Policy != Accept {
		t.Fatalf("policy %v", rs.Policy)
	}
	if !strings.Contains(rs.String(), "chain output  # filter, priority -10, policy accept") {
		t.Fatalf("String() does not say policy accept:\n%s", rs)
	}
	check(t, rs, []vcase{
		{"out to anywhere", tcp(HookOutput, box, stranger, 40000, 443), Accept},
		{"in from anywhere", udp(HookInput, stranger, box, 5000, 53), Accept},
		{"forwarded", tcp(HookForward, stranger, db, 40000, 80), Accept},
		{"in to ssh from anywhere", tcp(HookInput, gray, box, 40000, 22), Accept},
	})
}

func TestBuild_Blocks(t *testing.T) {
	rs := Build(fixture(), []Block{blk(stranger, "tcp", 4444)}, now)
	other := netip.MustParseAddr("203.0.113.10")
	check(t, rs, []vcase{
		{"out to the block", tcp(HookOutput, box, stranger, 40000, 4444), Drop},
		{"forwarded to the block", tcp(HookForward, db, stranger, 40000, 4444), Drop},
		{"same address, other port", tcp(HookOutput, box, stranger, 40000, 4445), Accept},
		{"same endpoint, other protocol", udp(HookOutput, box, stranger, 40000, 4444), Accept},
		{"same port, other address", tcp(HookOutput, box, other, 40000, 4444), Accept},
	})
}

// The scorer shares a subnet with the red team: nothing inbound is cut.
func TestBuild_InboundNeverBlocked(t *testing.T) {
	rs := Build(fixture(), []Block{blk(stranger, "tcp", 4444)}, now)
	in := tcp(HookInput, stranger, box, 4444, 80)
	reply := tcp(HookInput, stranger, box, 4444, 40000)
	reply.Reply, reply.State = true, StateEstablished
	check(t, rs, []vcase{{"in from the block's address", in, Accept}, {"a reply from it", reply, Accept}})
}

func TestBuild_ProtectedNeverBlocked(t *testing.T) {
	c := fixture()
	bare := Build(c, nil, now).String()
	blocks := []Block{blk(jump, "tcp", 22), blk(peer, "tcp", 7443), blk(gray, "tcp", 22), blk(resolver, "udp", 53),
		{Addr: stranger, Proto: "icmp", Port: 1}, {Addr: stranger, Proto: "tcp"}, {Proto: "tcp", Port: 1}}
	if got := Build(c, blocks, now).String(); got != bare {
		t.Fatalf("a protected or malformed block reached the table:\n%s", got)
	}
}

func TestBuild_AgentPorts(t *testing.T) {
	rs := Build(fixture(), nil, now)
	check(t, rs, []vcase{
		{"jump box to the agent port", tcp(HookInput, jump, box, 40000, 7443), Accept},
		{"peer to the agent port", tcp(HookInput, peer, box, 40000, 7443), Accept},
		{"stranger to the agent port", tcp(HookInput, stranger, box, 40000, 7443), Drop},
		{"stranger to ssh", tcp(HookInput, stranger, box, 40000, 22), Accept},
		{"box to a stranger's 7443", tcp(HookOutput, box, stranger, 40000, 7443), Accept},
	})
}

func TestBuild_BlockCap(t *testing.T) {
	var blocks []Block
	for i := 0; i < 600; i++ {
		blocks = append(blocks, blk(netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}), "tcp", 4444))
	}
	rs := Build(fixture(), blocks, now)
	n := 0
	for _, r := range rs.Output {
		if r.Action == Drop && r.CT != CTInvalid {
			n++
		}
	}
	if n != MaxBlocks {
		t.Fatalf("%d drops, want %d", n, MaxBlocks)
	}
	check(t, rs, []vcase{
		{"the lowest address is kept", tcp(HookOutput, box, blocks[0].Addr, 40000, 4444), Drop},
		{"the highest is cut", tcp(HookOutput, box, blocks[599].Addr, 40000, 4444), Accept},
	})
	rev := slices.Clone(blocks)
	slices.Reverse(rev)
	if Build(fixture(), rev, now).String() != rs.String() {
		t.Fatal("the table depends on the order of the blocks")
	}
	if _, over := Select(fixture(), blocks); over != 600-MaxBlocks {
		t.Fatalf("over = %d", over)
	}
}

func TestBuild_DNSPin(t *testing.T) {
	q := udp(HookOutput, box, resolver, 40000, 53)
	check(t, Build(fixture(), nil, now), []vcase{{"no pin: dns passes", q, Accept}})
	c := fixture()
	c.DNS.Pin = true
	marked := q
	marked.Mark = DNSMark
	dot := tcp(HookOutput, box, resolver, 40000, 853)
	check(t, Build(c, nil, now), []vcase{
		{"pin, switch off: dns dropped", q, Drop},
		{"pin, switch off: even the stub's", marked, Drop},
		{"pin: dns over tcp dropped", tcp(HookOutput, box, resolver, 40000, 53), Drop},
		{"pin: dot dropped", dot, Drop},
		{"pin: other traffic passes", tcp(HookOutput, box, stranger, 40000, 443), Accept},
	})
	c.DNS.Enabled = true
	check(t, Build(c, nil, now), []vcase{
		{"pin, switch on: the stub's query passes", marked, Accept},
		{"pin, switch on: anyone else's is dropped", q, Drop},
	})
}
