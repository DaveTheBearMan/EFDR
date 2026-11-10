// Package fw is the host firewall: a default-deny policy built from the
// deployment config, an evaluator that tests it without a kernel, and a
// netlink translator that applies it.
package fw

import (
	"fmt"
	"net/netip"
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
	Mark         uint32        // meta mark
	Action       Action
}

// Ruleset is the three base chains. Each has policy drop.
type Ruleset struct{ Input, Output, Forward []Rule }

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

// mirror is the rule for the reply packets of connections r allows: the
// same addresses and ports seen from the other end, in the reply direction
// of an established connection.
func mirror(r Rule) Rule {
	m := r
	m.CT, m.Mark = CTReply, 0
	m.Src, m.Dst = r.Dst, r.Src
	m.SPort, m.DPort = r.DPort, r.SPort
	switch {
	case r.Proto == unix.IPPROTO_ICMP && r.ICMPType == 8:
		m.ICMPType = 0 // echo-reply
	case r.Proto == unix.IPPROTO_ICMPV6 && r.ICMPType == 128:
		m.ICMPType = 129
	}
	return m
}

// Build turns the deployment config into the policy in force at now.
//
// A connection passes only while its opening direction matches an allow
// rule: that direction is checked on every packet, an allow rule accepts
// that direction only, and reply packets are accepted only by the mirror
// of such a rule. There is no rule that accepts
// "established" as such, so a connection opened before the table was
// loaded gets no free pass in either direction: a reverse shell goes
// silent both ways, a session to a scored port carries on.
func Build(c *config.Config, now time.Time) Ruleset {
	var rs Ruleset
	add := func(chain *[]Rule, edit func(*Rule)) {
		r := rule()
		edit(&r)
		*chain = append(*chain, r)
	}
	// allow adds a rule to chain and its mirror to the chain the replies
	// pass through.
	allow := func(chain, replies *[]Rule, edit func(*Rule)) {
		add(chain, func(r *Rule) { r.CT = CTOriginal; edit(r) })
		*replies = append(*replies, mirror((*chain)[len(*chain)-1]))
	}
	icmp := func(chain *[]Rule, proto uint8, types ...int) {
		for _, t := range types {
			add(chain, func(r *Rule) { r.Proto, r.ICMPType = proto, t })
		}
	}
	common := func(chain *[]Rule, v6 bool) {
		add(chain, func(r *Rule) { r.CT, r.Action = CTInvalid, Drop })
		add(chain, func(r *Rule) { r.CT, r.Proto = CTRelated, unix.IPPROTO_ICMP })
		if v6 {
			add(chain, func(r *Rule) { r.CT, r.Proto = CTRelated, unix.IPPROTO_ICMPV6 })
		}
	}
	xdr := union(c.Jump, c.Peers)
	in, out, fwd := &rs.Input, &rs.Output, &rs.Forward

	add(in, func(r *Rule) { r.Loopback = true })
	add(out, func(r *Rule) { r.Loopback = true })
	common(in, true)
	common(out, true)
	common(fwd, false)

	// Inbound.
	allow(in, out, func(r *Rule) { r.Proto, r.ICMPType = unix.IPPROTO_ICMP, 8 })
	allow(in, out, func(r *Rule) { r.Proto, r.ICMPType = unix.IPPROTO_ICMPV6, 128 })
	icmp(in, unix.IPPROTO_ICMPV6, 135, 136, 134)
	if c.DHCP {
		add(in, func(r *Rule) { r.Proto, r.SPort, r.DPort = unix.IPPROTO_UDP, 67, 68 })
	}
	for _, p := range c.Scored {
		allow(in, out, func(r *Rule) { r.Proto, r.DPort = protoNum(p.Proto), p.Port })
	}
	for _, src := range union(c.Jump, c.SSHFrom) {
		allow(in, out, func(r *Rule) { r.Src, r.Proto, r.DPort = &src, unix.IPPROTO_TCP, c.SSHPort })
	}
	for _, src := range xdr {
		for _, port := range c.XDRPorts {
			allow(in, out, func(r *Rule) { r.Src, r.Proto, r.DPort = &src, unix.IPPROTO_TCP, port })
		}
	}

	// Outbound.
	icmp(out, unix.IPPROTO_ICMPV6, 135, 136, 133)
	if c.DHCP {
		add(out, func(r *Rule) { r.Proto, r.SPort, r.DPort = unix.IPPROTO_UDP, 68, 67 })
	}
	for _, dst := range xdr {
		for _, port := range c.XDRPorts {
			allow(out, in, func(r *Rule) { r.Dst, r.Proto, r.DPort = &dst, unix.IPPROTO_TCP, port })
		}
	}
	for _, d := range c.AllowOut {
		allow(out, in, func(r *Rule) { r.Dst, r.Proto, r.DPort = &d.To.Prefix, protoNum(d.Proto), d.Port })
	}
	if c.DNSOn(now) && c.DNS.Resolver.IsValid() {
		res := netip.PrefixFrom(c.DNS.Resolver, c.DNS.Resolver.BitLen())
		allow(out, in, func(r *Rule) { r.Mark, r.Dst, r.Proto, r.DPort = DNSMark, &res, unix.IPPROTO_UDP, 53 })
	}

	// Forwarded: to and from containers. The original destination port of
	// a published connection is the same on its packets in both directions,
	// so that rule is its own mirror.
	for _, p := range c.Scored {
		add(fwd, func(r *Rule) { r.Proto, r.OrigDPort = protoNum(p.Proto), p.Port })
	}
	for _, d := range c.AllowOut {
		allow(fwd, fwd, func(r *Rule) { r.Dst, r.Proto, r.DPort = &d.To.Prefix, protoNum(d.Proto), d.Port })
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

// Verdict is the action of the first rule that matches p, or Drop.
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
	return Drop
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
		fmt.Fprintf(&b, "chain %s  # filter, priority -10, policy drop\n", [...]string{"input", "output", "forward"}[hook])
		for _, r := range chain {
			fmt.Fprintf(&b, "  %s\n", r.text(hook))
		}
	}
	return b.String()
}
