// Package fw is the host firewall: a policy-accept table built from the
// deployment config and the fleet's blocklist, an evaluator that tests it
// without a kernel, and a netlink translator that applies it.
package fw

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"xdr/internal/config"
)

// DNSMark is the socket mark carried by the DNS stub's upstream queries,
// the only packets allowed to leave for port 53.
const DNSMark uint32 = 0x58445201

// Action is what happens to a packet.
type Action int

const (
	Drop Action = iota
	Accept
)

func (a Action) String() string {
	if a == Accept {
		return "accept"
	}
	return "drop"
}

// CT is a rule's connection-tracking condition.
type CT int

const (
	CTAny      CT = iota
	CTInvalid     // ct state invalid
	CTOriginal    // ct direction original
	CTReply       // ct direction reply, ct state established or related
	CTRelated     // ct state related
)

// Rule is one line of a chain. A zero field matches anything, except
// ICMPType, where -1 does.
type Rule struct {
	Loopback     bool          // iif lo on input, oif lo on output
	CT           CT            //
	Proto        uint8         // unix.IPPROTO_*
	Src, Dst     *netip.Prefix //
	SPort, DPort uint16        //
	ICMPType     int           //
	OrigDPort    uint16        // ct status dnat and this original destination port
	NotDNAT      bool          // the connection was not destination-NATed
	Mark         uint32        // meta mark
	Action       Action
}

// Ruleset is the three base chains. Each has the policy of the set: Build
// makes it Accept (a zero Ruleset drops everything).
type Ruleset struct {
	Policy                 Action
	Input, Output, Forward []Rule
}

// Block is an endpoint the fleet found malicious: packets from this box to
// it are dropped.
type Block struct {
	Addr  netip.Addr
	Proto string // "tcp" or "udp"
	Port  uint16
}

// MaxBlocks is the most blocks one table holds.
const MaxBlocks = 512

func rule() Rule { return Rule{ICMPType: -1, Action: Accept} }

func protoNum(name string) uint8 {
	if name == "udp" {
		return unix.IPPROTO_UDP
	}
	return unix.IPPROTO_TCP
}

// union returns the distinct prefixes of the given lists, in order.
func union(lists ...[]config.Net) []netip.Prefix {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for _, l := range lists {
		for _, n := range l {
			if !seen[n.Prefix] {
				seen[n.Prefix] = true
				out = append(out, n.Prefix)
			}
		}
	}
	return out
}

// Select is the blocks the table will hold: those that are well formed and
// name no protected address (the jump box, the peers, ssh_from, the
// resolver), without repeats, in a fixed order (address, protocol, port),
// cut at MaxBlocks. over is how many valid ones the cut left out.
func Select(c *config.Config, blocks []Block) (kept []Block, over int) {
	protected := c.Protected()
	for _, b := range blocks {
		a := b.Addr.Unmap()
		if !a.IsValid() || b.Port == 0 || b.Proto != "tcp" && b.Proto != "udp" {
			continue
		}
		if slices.ContainsFunc(protected, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		kept = append(kept, Block{a, b.Proto, b.Port})
	}
	slices.SortFunc(kept, func(x, y Block) int {
		if c := x.Addr.Compare(y.Addr); c != 0 {
			return c
		}
		if c := strings.Compare(x.Proto, y.Proto); c != 0 {
			return c
		}
		return int(x.Port) - int(y.Port)
	})
	kept = slices.Compact(kept)
	if len(kept) > MaxBlocks {
		over, kept = len(kept)-MaxBlocks, kept[:MaxBlocks]
	}
	return kept, over
}

// Build turns the deployment config and the fleet's blocks into the policy
// in force at now.
//
// The policy is accept: what is malicious has to be found before it can be
// blocked, and a table that dropped by default would take a scored
// service offline. The table holds only these rules, in this order:
// loopback and invalid-state housekeeping; the agents' own ports, open to
// the jump box and the peers and shut to everyone else; one drop of
// outbound and forwarded packets to each block (never inbound: the scorer
// shares a subnet with the red team); and, with dns.pin, the DNS lockdown.
// SSH is not filtered here: sshd's AllowUsers and the gate decide.
func Build(c *config.Config, blocks []Block, now time.Time) Ruleset {
	rs := Ruleset{Policy: Accept}
	add := func(chain *[]Rule, edit func(*Rule)) {
		r := rule()
		edit(&r)
		*chain = append(*chain, r)
	}
	in, out, fwd := &rs.Input, &rs.Output, &rs.Forward

	add(in, func(r *Rule) { r.Loopback = true })
	add(out, func(r *Rule) { r.Loopback = true })
	for _, chain := range []*[]Rule{in, out, fwd} {
		add(chain, func(r *Rule) { r.CT, r.Action = CTInvalid, Drop })
	}

	for _, src := range union(c.Jump, c.Peers) {
		for _, port := range c.XDRPorts {
			add(in, func(r *Rule) { r.Src, r.Proto, r.DPort = &src, unix.IPPROTO_TCP, port })
		}
	}
	for _, port := range c.XDRPorts {
		add(in, func(r *Rule) { r.Proto, r.DPort, r.Action = unix.IPPROTO_TCP, port, Drop })
	}

	kept, _ := Select(c, blocks)
	if len(kept) > 0 {
		// What leaves from a scored port answers someone who connected to
		// it, whatever that host's own source port was: never a block's
		// target.
		for _, p := range c.Scored {
			add(out, func(r *Rule) { r.Proto, r.SPort = protoNum(p.Proto), p.Port })
		}
	}
	for _, b := range kept {
		dst := netip.PrefixFrom(b.Addr, b.Addr.BitLen())
		add(out, func(r *Rule) { r.Dst, r.Proto, r.DPort, r.Action = &dst, protoNum(b.Proto), b.Port, Drop })
		// Forwarded: a published port is seen after DNAT, its destination
		// the container, which may be what a rule names: not cut.
		add(fwd, func(r *Rule) {
			r.Dst, r.Proto, r.DPort, r.Action, r.NotDNAT = &dst, protoNum(b.Proto), b.Port, Drop, true
		})
	}

	if c.DNS.Pin {
		if c.DNSOn(now) && c.DNS.Resolver.IsValid() {
			res := netip.PrefixFrom(c.DNS.Resolver, c.DNS.Resolver.BitLen())
			add(out, func(r *Rule) { r.Mark, r.Dst, r.Proto, r.DPort = DNSMark, &res, unix.IPPROTO_UDP, 53 })
		}
		add(out, func(r *Rule) { r.Proto, r.DPort, r.Action = unix.IPPROTO_UDP, 53, Drop })
		add(out, func(r *Rule) { r.Proto, r.DPort, r.Action = unix.IPPROTO_TCP, 53, Drop })
		add(out, func(r *Rule) { r.Proto, r.DPort, r.Action = unix.IPPROTO_TCP, 853, Drop })
	}
	return rs
}

// Hooks a packet is seen at.
const (
	HookInput = iota
	HookOutput
	HookForward
)

// Connection-tracking states.
const (
	StateNew = iota
	StateEstablished
	StateRelated
	StateInvalid
)

// Packet is what the evaluator needs to know about a packet.
type Packet struct {
	Hook         int
	Loopback     bool // arrived on, or leaves by, the loopback interface
	State        int
	Reply        bool // travels in the reply direction of its connection
	Proto        uint8
	Src, Dst     netip.Addr
	SPort, DPort uint16
	ICMPType     int
	DNAT         bool   // the connection was destination-NATed
	OrigDPort    uint16 // its destination port before that
	Mark         uint32
}

// Verdict is the action of the first rule that matches p, or the policy.
func (rs Ruleset) Verdict(p Packet) Action {
	chain := rs.Input
	switch p.Hook {
	case HookOutput:
		chain = rs.Output
	case HookForward:
		chain = rs.Forward
	}
	for _, r := range chain {
		if r.matches(p) {
			return r.Action
		}
	}
	return rs.Policy
}

func (r Rule) matches(p Packet) bool {
	if r.Loopback && !(p.Loopback && p.Hook != HookForward) {
		return false
	}
	switch r.CT {
	case CTInvalid:
		if p.State != StateInvalid {
			return false
		}
	case CTOriginal:
		if p.Reply || p.State == StateInvalid {
			return false
		}
	case CTReply:
		if !p.Reply || p.State != StateEstablished && p.State != StateRelated {
			return false
		}
	case CTRelated:
		if p.State != StateRelated {
			return false
		}
	}
	if r.Proto != 0 && r.Proto != p.Proto {
		return false
	}
	if r.Src != nil && !r.Src.Contains(p.Src.Unmap()) {
		return false
	}
	if r.Dst != nil && !r.Dst.Contains(p.Dst.Unmap()) {
		return false
	}
	if r.SPort != 0 && r.SPort != p.SPort || r.DPort != 0 && r.DPort != p.DPort {
		return false
	}
	if r.ICMPType >= 0 && r.ICMPType != p.ICMPType {
		return false
	}
	if r.OrigDPort != 0 && !(p.DNAT && p.OrigDPort == r.OrigDPort) {
		return false
	}
	if r.NotDNAT && p.DNAT {
		return false
	}
	if r.Mark != 0 && r.Mark != p.Mark {
		return false
	}
	return true
}

var protoNames = map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp", unix.IPPROTO_ICMP: "icmp", unix.IPPROTO_ICMPV6: "icmpv6"}

func (r Rule) text(hook int) string {
	var w []string
	if r.Loopback {
		w = append(w, map[int]string{HookInput: "iif lo", HookOutput: "oif lo"}[hook])
	}
	switch r.CT {
	case CTInvalid:
		w = append(w, "ct state invalid")
	case CTOriginal:
		w = append(w, "ct direction original")
	case CTReply:
		w = append(w, "ct direction reply ct state established,related")
	case CTRelated:
		w = append(w, "ct state related")
	}
	if r.Mark != 0 {
		w = append(w, fmt.Sprintf("meta mark %#x", r.Mark))
	}
	addr := func(dir string, p *netip.Prefix) {
		fam, s := "ip", p.String()
		if p.Addr().Is6() {
			fam = "ip6"
		}
		if p.IsSingleIP() {
			s = p.Addr().String()
		}
		w = append(w, fam+" "+dir+" "+s)
	}
	if r.Src != nil {
		addr("saddr", r.Src)
	}
	if r.Dst != nil {
		addr("daddr", r.Dst)
	}
	if r.NotDNAT {
		w = append(w, "ct status != dnat")
	}
	name := protoNames[r.Proto]
	switch {
	case r.OrigDPort != 0:
		w = append(w, fmt.Sprintf("ct status dnat meta l4proto %s ct original proto-dst %d", name, r.OrigDPort))
	case r.ICMPType >= 0:
		w = append(w, fmt.Sprintf("%s type %d", name, r.ICMPType))
	case r.Proto != 0 && r.SPort == 0 && r.DPort == 0:
		w = append(w, "meta l4proto "+name)
	}
	if r.SPort != 0 {
		w = append(w, fmt.Sprintf("%s sport %d", name, r.SPort))
	}
	if r.DPort != 0 {
		w = append(w, fmt.Sprintf("%s dport %d", name, r.DPort))
	}
	return strings.Join(append(w, r.Action.String()), " ")
}

// String is the ruleset in nft-like text, one rule per line.
func (rs Ruleset) String() string {
	var b strings.Builder
	b.WriteString("table inet xdr\n")
	for hook, chain := range [][]Rule{rs.Input, rs.Output, rs.Forward} {
		fmt.Fprintf(&b, "chain %s  # filter, priority -10, policy %s\n", [...]string{"input", "output", "forward"}[hook], rs.Policy)
		for _, r := range chain {
			fmt.Fprintf(&b, "  %s\n", r.text(hook))
		}
	}
	return b.String()
}
