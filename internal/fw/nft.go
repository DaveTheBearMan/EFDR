package fw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"reflect"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	tableName = "xdr"
	priority  = -10
)

var chainNames = [...]string{HookInput: "input", HookOutput: "output", HookForward: "forward"}

// Firewall is the xdr table in the kernel, in the network namespace of the
// thread that called Open.
type Firewall struct {
	conn *nftables.Conn
	// seen is every chain's rules, as the bytes the kernel reported right
	// after the last Apply. Drift is any difference from that: comparing
	// what the kernel says with what the kernel said needs no knowledge of
	// how it rewrites what we send, nor of expressions we never use.
	seen map[string][]string
}

// Open prepares to manage the table. It fails if nftables cannot be reached.
func Open() (*Firewall, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	if _, err := c.ListTablesOfFamily(nftables.TableFamilyINet); err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return &Firewall{conn: c}, nil
}

// Close releases the firewall handle. The table stays.
func (f *Firewall) Close() error { return nil }

func table() *nftables.Table {
	return &nftables.Table{Family: nftables.TableFamilyINet, Name: tableName}
}

// Apply replaces the table with rs in one transaction: there is no moment
// at which the old rules are gone and the new ones are not yet in force.
func (f *Firewall) Apply(rs Ruleset) error {
	c, t := f.conn, table()
	c.AddTable(t) // so that the delete below cannot fail
	c.DelTable(t)
	c.AddTable(t)
	drop := nftables.ChainPolicyDrop
	hooks := [...]*nftables.ChainHook{HookInput: nftables.ChainHookInput, HookOutput: nftables.ChainHookOutput, HookForward: nftables.ChainHookForward}
	want := map[string]int{}
	for hook, rules := range [...][]Rule{HookInput: rs.Input, HookOutput: rs.Output, HookForward: rs.Forward} {
		ch := c.AddChain(&nftables.Chain{
			Name: chainNames[hook], Table: t, Type: nftables.ChainTypeFilter,
			Hooknum: hooks[hook], Priority: nftables.ChainPriorityRef(priority), Policy: &drop,
		})
		for _, r := range rules {
			c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: exprs(r, hook)})
		}
		want[chainNames[hook]] = len(rules)
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	seen, ok, err := f.read()
	if err != nil {
		return fmt.Errorf("nftables: reading the table back: %w", err)
	}
	if !ok {
		return errors.New("nftables: the table is not as it was just written")
	}
	for name, n := range want {
		if len(seen[name]) != n {
			return fmt.Errorf("nftables: chain %s has %d rules right after %d were written", name, len(seen[name]), n)
		}
	}
	f.seen = seen
	return nil
}

// read returns the rules of the three chains. ok is false when the table,
// a chain or a chain's hook, priority or policy is not ours.
func (f *Firewall) read() (seen map[string][]string, ok bool, err error) {
	chains, err := f.conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return nil, false, err
	}
	hooks := map[string]nftables.ChainHook{"input": unix.NF_INET_LOCAL_IN, "output": unix.NF_INET_LOCAL_OUT, "forward": unix.NF_INET_FORWARD}
	seen = map[string][]string{}
	n := 0
	for _, ch := range chains {
		if ch.Table.Name != tableName {
			continue
		}
		n++
		hook, ours := hooks[ch.Name]
		if !ours || ch.Type != nftables.ChainTypeFilter ||
			ch.Hooknum == nil || *ch.Hooknum != hook ||
			ch.Priority == nil || *ch.Priority != priority ||
			ch.Policy == nil || *ch.Policy != nftables.ChainPolicyDrop {
			return nil, false, nil
		}
		seen[ch.Name] = []string{}
	}
	if n != len(hooks) || len(seen) != len(hooks) {
		return nil, false, nil
	}
	rules, err := dumpRules()
	if err != nil {
		if notExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	for _, r := range rules {
		seen[r.chain] = append(seen[r.chain], r.exprs)
	}
	return seen, len(seen) == len(hooks), nil
}

// rawRule is one rule of the table as the kernel dumps it.
type rawRule struct {
	chain  string
	handle uint64
	exprs  string // the NFTA_RULE_EXPRESSIONS attribute, undecoded
}

// dumpRules lists the table's rules in kernel order. It asks the kernel
// directly: the nftables package fails to decode some of the expressions
// it encodes (ct with a direction), and bytes it cannot decode are still
// bytes that have to match.
func dumpRules() ([]rawRule, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(tableName + "\x00")}})
	if err != nil {
		return nil, err
	}
	// nfgenmsg: family, version, resource id.
	body := append([]byte{unix.NFPROTO_INET, unix.NFNETLINK_V0, 0, 0}, attrs...)
	msgs, err := conn.Execute(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Dump,
		},
		Data: body,
	})
	if err != nil {
		return nil, err
	}
	var rules []rawRule
	for _, m := range msgs {
		if len(m.Data) < 4 {
			continue
		}
		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			return nil, err
		}
		ad.ByteOrder = binary.BigEndian
		var r rawRule
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_RULE_CHAIN:
				r.chain = ad.String()
			case unix.NFTA_RULE_HANDLE:
				r.handle = ad.Uint64()
			case unix.NFTA_RULE_EXPRESSIONS:
				r.exprs = string(ad.Bytes())
			}
		}
		if err := ad.Err(); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// Drifted reports whether the table differs in any way from what the last
// Apply left: missing, a chain added, removed or re-hooked, a policy
// changed, or any rule added, removed or altered.
func (f *Firewall) Drifted() (bool, error) {
	seen, ok, err := f.read()
	if err != nil {
		return false, fmt.Errorf("nftables: %w", err)
	}
	return !ok || !reflect.DeepEqual(seen, f.seen), nil
}

// Remove deletes the table. A table that is already gone is not an error.
func (f *Firewall) Remove() error {
	f.conn.DelTable(table())
	if err := f.conn.Flush(); err != nil && !notExist(err) {
		return fmt.Errorf("nftables: %w", err)
	}
	f.seen = nil
	return nil
}

func notExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT)
}

// exprs translates one rule for the chain at hook. The expression lists
// are the ones nft generates for the statements in Rule.text.
func exprs(r Rule, hook int) []expr.Any {
	var e []expr.Any
	eq := func(data []byte) { e = append(e, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}) }
	meta := func(key expr.MetaKey, data []byte) {
		e = append(e, &expr.Meta{Key: key, Register: 1})
		eq(data)
	}
	// bits matches when the 32-bit value in register 1 has any of mask set.
	bits := func(mask uint32) {
		e = append(e,
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: binaryutil.NativeEndian.PutUint32(mask), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)})
	}
	ctState := func(mask uint32) {
		e = append(e, &expr.Ct{Register: 1, Key: expr.CtKeySTATE})
		bits(mask)
	}
	transport := func(offset, length uint32, data []byte) {
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: length})
		eq(data)
	}
	port := func(p uint16) []byte { return binary.BigEndian.AppendUint16(nil, p) }

	if r.Loopback {
		key := expr.MetaKeyIIFNAME
		if hook == HookOutput {
			key = expr.MetaKeyOIFNAME
		}
		name := make([]byte, unix.IFNAMSIZ)
		copy(name, "lo")
		meta(key, name)
	}
	switch r.CT {
	case CTInvalid:
		ctState(expr.CtStateBitINVALID)
	case CTOriginal:
		e = append(e, &expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION})
		eq([]byte{0}) // IP_CT_DIR_ORIGINAL
	case CTReply:
		e = append(e, &expr.Ct{Register: 1, Key: expr.CtKeyDIRECTION})
		eq([]byte{1}) // IP_CT_DIR_REPLY
		ctState(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
	case CTRelated:
		ctState(expr.CtStateBitRELATED)
	}
	if r.Mark != 0 {
		meta(expr.MetaKeyMARK, binaryutil.NativeEndian.PutUint32(r.Mark))
	}

	// The table is of family inet: anything that reads the network header
	// has to say which protocol's header it means.
	family := byte(0)
	switch {
	case r.Src != nil:
		family = nfproto(r.Src.Addr())
	case r.Dst != nil:
		family = nfproto(r.Dst.Addr())
	case r.ICMPType >= 0 && r.Proto == unix.IPPROTO_ICMP:
		family = unix.NFPROTO_IPV4
	case r.ICMPType >= 0 && r.Proto == unix.IPPROTO_ICMPV6:
		family = unix.NFPROTO_IPV6
	}
	if family != 0 {
		meta(expr.MetaKeyNFPROTO, []byte{family})
	}
	addr := func(p *netip.Prefix, v4off, v6off uint32) {
		a := p.Masked().Addr()
		off, raw := v4off, a.AsSlice()
		if a.Is6() {
			off = v6off
		}
		e = append(e, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: uint32(len(raw))})
		if p.Bits() < a.BitLen() {
			mask := make([]byte, len(raw))
			for i := 0; i < p.Bits(); i++ {
				mask[i/8] |= 0x80 >> (i % 8)
			}
			e = append(e, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(raw)), Mask: mask, Xor: make([]byte, len(raw))})
		}
		eq(raw)
	}
	if r.Src != nil {
		addr(r.Src, 12, 8)
	}
	if r.Dst != nil {
		addr(r.Dst, 16, 24)
	}
	if r.OrigDPort != 0 {
		e = append(e, &expr.Ct{Register: 1, Key: expr.CtKeySTATUS})
		bits(0x20) // IPS_DST_NAT
	}
	if r.Proto != 0 {
		meta(expr.MetaKeyL4PROTO, []byte{r.Proto})
	}
	if r.OrigDPort != 0 {
		e = append(e, &expr.Ct{Register: 1, Key: expr.CtKeyPROTODST, Direction: 0}) // original direction
		eq(port(r.OrigDPort))
	}
	if r.ICMPType >= 0 {
		transport(0, 1, []byte{byte(r.ICMPType)})
	}
	if r.SPort != 0 {
		transport(0, 2, port(r.SPort))
	}
	if r.DPort != 0 {
		transport(2, 2, port(r.DPort))
	}
	kind := expr.VerdictDrop
	if r.Action == Accept {
		kind = expr.VerdictAccept
	}
	return append(e, &expr.Verdict{Kind: kind})
}

func nfproto(a netip.Addr) byte {
	if a.Is4() {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}
