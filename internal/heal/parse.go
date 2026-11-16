// Package heal finds what red team planted to isolate a box: firewall
// rules, blackhole routes, hosts.deny lines. Everything here is a pure
// function over the text a tool printed; nothing runs a command. What a
// parser returns is exactly what the caller may remove, and it never
// returns anything that could take a scored service offline.
package heal

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"xdr/internal/config"
)

// NftRule is one rule of a foreign table, as `nft -a list ruleset` shows
// it: removed with `nft delete rule <family> <table> <chain> handle <n>`.
type NftRule struct {
	Chain  string
	Handle uint64
}

// Table is a table other than the agent's own, with the rules in it that
// block the fleet or the agent's ports. Only the listed rules are to be
// removed, never the table: it may hold others' rules.
type Table struct {
	Family, Name string
	Rules        []NftRule
}

// skipTable: the agent's own table, by family and name. Every other table
// is judged, whatever it is called; its NAT chains are left by their type.
func skipTable(family, name string) bool { return family == "inet" && name == "xdr" }

// skipChain: Docker, Kubernetes, Calico, CNI and libvirt keep their own
// chains (forwarding isolation among them), whatever table they sit in.
func skipChain(name string) bool {
	u := strings.ToUpper(name)
	for _, p := range []string{"DOCKER", "KUBE", "CALI", "CNI-", "LIBVIRT"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return false
}

func isAddrChar(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.' || r == '/'
}

// parsePrefix is an address or a block; ok is false for anything else.
func parsePrefix(tok string) (netip.Prefix, bool) {
	if q, err := netip.ParsePrefix(tok); err == nil {
		return q.Masked(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// inFleet: p lies wholly inside one of the fleet's nets. A block wider
// than the fleet's (192.0.0.0/8 around a /24) does not name the fleet: it
// takes others with it.
func inFleet(p netip.Prefix, fleet []netip.Prefix) bool {
	for _, f := range fleet {
		if f.Addr().Is4() == p.Addr().Is4() && f.Bits() <= p.Bits() && f.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// namesFleet reports whether text names an address in, or a block inside,
// one of the fleet's.
func namesFleet(text string, fleet []netip.Prefix) bool {
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return !isAddrChar(r) }) {
		if p, ok := parsePrefix(tok); ok && inFleet(p, fleet) {
			return true
		}
	}
	return false
}

// match is one address or port match of a rule: its values (one, or a
// set's or list's elements) and whether it is negated.
type match struct {
	port bool
	neg  bool
	vals []string
}

// portRange reads a port or a range ("1-1024", iptables' "1:1024").
func portRange(v string) (lo, hi int, ok bool) {
	a, b, isRange := strings.Cut(v, "-")
	if !isRange {
		a, b, isRange = strings.Cut(v, ":")
	}
	if !isRange {
		b = a
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || x < 0 || y > 65535 || x > y {
		return 0, 0, false
	}
	return x, y, true
}

// blocks judges a rule by its matches, negated ones left out: it is a
// blocker when one address match names only the fleet (an address or a
// block inside a fleet net, or a set of them) or one port match names only
// agent ports, each as a single port; and no port match takes in a scored
// port anywhere (a range or a set that holds one), nor anything it cannot
// read. When unsure the rule is left.
func blocks(ms []match, fleet []netip.Prefix, ports []uint16, scored []config.Port) bool {
	fleetOnly, agentOnly := false, false
	for _, m := range ms {
		if m.neg || len(m.vals) == 0 {
			continue
		}
		if m.port {
			all := true
			for _, v := range m.vals {
				lo, hi, ok := portRange(v)
				if !ok {
					return false
				}
				for _, s := range scored {
					if int(s.Port) >= lo && int(s.Port) <= hi {
						return false
					}
				}
				all = all && lo == hi && slices.Contains(ports, uint16(lo))
			}
			agentOnly = agentOnly || all
			continue
		}
		all := true
		for _, v := range m.vals {
			p, ok := parsePrefix(v)
			all = all && ok && inFleet(p, fleet)
		}
		fleetOnly = fleetOnly || all
	}
	return fleetOnly || agentOnly
}

// nftMatches reads the address and port matches of an nft rule:
// "saddr|daddr|dport|sport [!=|==] VALUE", VALUE a word or "{ a, b }".
func nftMatches(rule string) []match {
	rule = strings.NewReplacer("{", " { ", "}", " } ", ",", " ").Replace(rule)
	f := strings.Fields(rule)
	var out []match
	for i := 0; i < len(f); i++ {
		var m match
		switch f[i] {
		case "saddr", "daddr":
		case "dport", "sport":
			m.port = true
		default:
			continue
		}
		j := i + 1
		if j < len(f) && (f[j] == "!=" || f[j] == "==") {
			m.neg = f[j] == "!="
			j++
		}
		if j >= len(f) {
			break
		}
		if f[j] == "{" {
			for j++; j < len(f) && f[j] != "}"; j++ {
				m.vals = append(m.vals, f[j])
			}
		} else {
			m.vals = []string{f[j]}
		}
		out = append(out, m)
		i = j
	}
	return out
}

// iptMatches reads the address and port matches of an iptables-save rule's
// words: -s/-d (a comma list), --dport/--sport, --dports/--sports (a comma
// list of ports and ranges), each negated by a "!" before it (or after
// the option, the old way).
func iptMatches(f []string) []match {
	var out []match
	neg := false
	for i := 0; i < len(f); i++ {
		w := f[i]
		if w == "!" {
			neg = true
			continue
		}
		var m match
		switch w {
		case "-s", "--source", "-d", "--destination":
		case "--dport", "--sport", "--dports", "--sports", "--destination-port", "--source-port", "--destination-ports", "--source-ports":
			m.port = true
		default:
			neg = false
			continue
		}
		m.neg, neg = neg, false
		j := i + 1
		if j < len(f) && f[j] == "!" {
			m.neg = true
			j++
		}
		if j >= len(f) {
			break
		}
		m.vals = strings.Split(f[j], ",")
		out = append(out, m)
		i = j
	}
	return out
}

var nftComment = regexp.MustCompile(`comment\s+"[^"]*"`)

// cutHandle splits a trailing "# handle N" off a line of nft output; the
// handle is 0 when there is none.
func cutHandle(line string) (string, uint64) {
	i := strings.LastIndex(line, "# handle ")
	if i < 0 {
		return line, 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(line[i+len("# handle "):]), 10, 64)
	if err != nil {
		return line, 0
	}
	return strings.TrimSpace(line[:i]), n
}

// NftBlockers reads `nft -a list ruleset` and returns, for each table
// other than ours, in its chains other than NAT and the container
// runtimes', the drop and reject rules that plainly block the fleet or one
// of the agent's ports (see blocks). A rule that takes in a scored port is
// never returned.
func NftBlockers(ruleset string, fleet []netip.Prefix, ports []uint16, scored []config.Port) []Table {
	var out []Table
	var cur *Table
	var chain string
	skipT, skipC := false, false
	flush := func() {
		if cur != nil && len(cur.Rules) > 0 {
			out = append(out, *cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(ruleset, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue // nft's warnings, as "# Warning: table ip filter is managed by iptables-nft"
		}
		// Every line of `nft -a list ruleset` may end in "# handle N":
		// tables and chains as well as rules.
		line, handle := cutHandle(line)
		f := strings.Fields(line)
		switch {
		case len(f) == 0 || line == "}":
			continue
		case f[0] == "table" && len(f) >= 4 && f[len(f)-1] == "{":
			flush()
			skipT = skipTable(f[1], f[2])
			cur = &Table{Family: f[1], Name: f[2]}
			chain, skipC = "", false
		case f[0] == "chain" && len(f) >= 3:
			chain = f[1]
			skipC = skipChain(chain)
		case f[0] == "type" || f[0] == "policy" || f[0] == "set" || f[0] == "map" || f[0] == "elements":
			if f[0] == "type" && len(f) > 1 && f[1] == "nat" {
				skipC = true
			}
		default:
			if cur == nil || chain == "" || skipT || skipC {
				continue
			}
			if handle == 0 {
				continue
			}
			h := handle
			rule := nftComment.ReplaceAllString(line, "")
			rf := strings.Fields(rule)
			if len(rf) == 0 || (rf[len(rf)-1] != "drop" && rf[len(rf)-1] != "reject" && !strings.Contains(rule, " reject ")) {
				continue
			}
			if blocks(nftMatches(rule), fleet, ports, scored) {
				cur.Rules = append(cur.Rules, NftRule{Chain: chain, Handle: h})
			}
		}
	}
	flush()
	return out
}

// split breaks a line into words, honouring double quotes (iptables-save
// quotes comments) and dropping the quotes.
func split(line string) []string {
	var out []string
	var b strings.Builder
	in, have := false, false
	for _, r := range line {
		switch {
		case r == '"':
			in, have = !in, true
		case (r == ' ' || r == '\t') && !in:
			if have {
				out = append(out, b.String())
				b.Reset()
				have = false
			}
		default:
			b.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, b.String())
	}
	return out
}

// IptablesBlockers reads iptables-save (or ip6tables-save) output and
// returns each DROP or REJECT rule that names a fleet address or an agent
// port, as the argument list of `iptables -t <table> -D ...`. The nat and
// container chains are left alone, as are rules for scored ports only.
func IptablesBlockers(save string, fleet []netip.Prefix, ports []uint16, scored []config.Port) [][]string {
	var out [][]string
	table := ""
	for _, line := range strings.Split(save, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "*") {
			table = line[1:]
			continue
		}
		if !strings.HasPrefix(line, "-A ") || table == "" || table == "nat" {
			continue
		}
		f := split(line)
		if len(f) < 3 || skipChain(f[1]) {
			continue
		}
		target := ""
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "-j" || f[i] == "-g" {
				target = f[i+1]
			}
		}
		if target != "DROP" && target != "REJECT" {
			continue
		}
		// The comment text is left out of the judgement.
		var judge []string
		for i := 0; i < len(f); i++ {
			if f[i] == "--comment" {
				i++
				continue
			}
			judge = append(judge, f[i])
		}
		if !blocks(iptMatches(judge), fleet, ports, scored) {
			continue
		}
		args := append([]string{"-t", table, "-D", f[1]}, f[2:]...)
		out = append(out, args)
	}
	return out
}

func blockAction(f []string) bool {
	for _, w := range f {
		switch w {
		case "blackhole", "unreachable", "prohibit":
			return true
		}
	}
	return false
}

// RouteBlockers reads `ip rule` and `ip route` and returns the commands
// (`ip rule del ...`, `ip route del ...`, each one line, words separated
// by single spaces) for the blackhole, unreachable and prohibit entries
// that name a fleet address.
func RouteBlockers(rules, routes string, fleet []netip.Prefix) []string {
	var out []string
	for _, line := range strings.Split(rules, "\n") {
		pref, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
		f := strings.Fields(rest)
		if !ok || len(f) == 0 || !blockAction(f) || !namesFleet(rest, fleet) {
			continue
		}
		if _, err := strconv.Atoi(pref); err != nil {
			continue
		}
		out = append(out, "ip rule del pref "+pref+" "+strings.Join(f, " "))
	}
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !blockAction(f[:1]) || !namesFleet(f[1], fleet) {
			continue
		}
		out = append(out, "ip route del "+strings.Join(f, " "))
	}
	return out
}

// denyNames: a hosts.deny token names a fleet address: an address, a CIDR
// block, or the wrappers' trailing-dot prefix ("192.0.2.").
func denyNames(tok string, fleet []netip.Prefix) bool {
	tok = strings.Trim(tok, "[]")
	if strings.HasSuffix(tok, ".") {
		parts := strings.Split(strings.TrimSuffix(tok, "."), ".")
		if len(parts) >= 1 && len(parts) <= 3 {
			full := append(append([]string{}, parts...), "0", "0", "0")[:4]
			if a, err := netip.ParseAddr(strings.Join(full, ".")); err == nil {
				return namesFleet(netip.PrefixFrom(a, 8*len(parts)).String(), fleet)
			}
		}
		return false
	}
	return namesFleet(tok, fleet)
}

// fieldsOf splits a hosts.deny line at its colons, those inside brackets
// ([2001:db8::7]) aside.
func fieldsOf(line string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range line {
		switch r {
		case '[':
			depth++
		case ']':
			depth--
		case ':':
			if depth == 0 {
				out = append(out, line[start:i])
				start = i + 1
			}
		}
	}
	return append(out, line[start:])
}

// DenyLines returns the lines of /etc/hosts.deny whose clients are only
// fleet addresses, as they are written there. A line that also names
// others, or has an EXCEPT, is left, as are comments.
func DenyLines(hostsDeny string, fleet []netip.Prefix) []string {
	var out []string
	for _, line := range strings.Split(hostsDeny, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := fieldsOf(line)
		if len(fs) < 2 || slices.Contains(strings.Fields(line), "EXCEPT") {
			continue
		}
		toks := strings.FieldsFunc(fs[1], func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
		all := len(toks) > 0
		for _, tok := range toks {
			all = all && denyNames(tok, fleet)
		}
		if all {
			out = append(out, line)
		}
	}
	return out
}
