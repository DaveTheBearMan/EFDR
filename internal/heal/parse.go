// Package heal finds what red team planted to isolate a box: firewall
// rules, blackhole routes, hosts.deny lines. Everything here is a pure
// function over the text a tool printed; nothing runs a command. What a
// parser returns is exactly what the caller may remove, and it never
// returns anything that could take a scored service offline.
package heal

import (
	"net/netip"
	"regexp"
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

// ours and the tables of container runtimes: never touched.
func skipTable(name string) bool {
	switch {
	case name == "xdr" || name == "nat":
		return true
	}
	for _, p := range []string{"docker", "libvirt", "kube", "cali"} {
		if strings.HasPrefix(strings.ToLower(name), p) {
			return true
		}
	}
	return false
}

// skipChain: Docker, libvirt and the like keep their own chains.
func skipChain(name string) bool {
	u := strings.ToUpper(name)
	return strings.HasPrefix(u, "DOCKER") || strings.HasPrefix(u, "LIBVIRT") || strings.HasPrefix(u, "KUBE-") || strings.HasPrefix(u, "CNI-")
}

func isAddrChar(r rune) bool {
	return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == ':' || r == '.' || r == '/'
}

// namesFleet reports whether text names an address in, or a block
// overlapping, one of the fleet's.
func namesFleet(text string, fleet []netip.Prefix) bool {
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool { return !isAddrChar(r) }) {
		var p netip.Prefix
		if q, err := netip.ParsePrefix(tok); err == nil {
			p = q
		} else if a, err := netip.ParseAddr(tok); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			continue
		}
		for _, f := range fleet {
			if f.Overlaps(p) {
				return true
			}
		}
	}
	return false
}

// portsIn is every port a match names after dport, sport, --dport and
// the like: single ports, lists and sets; a range names each end.
var portRe = regexp.MustCompile(`(?:dport|sport|dports|sports)\s+(?:!=\s*)?(\{[^}]*\}|[0-9,:\-]+)`)

func portsIn(text string) []uint16 {
	var out []uint16
	for _, m := range portRe.FindAllStringSubmatch(text, -1) {
		for _, f := range strings.FieldsFunc(m[1], func(r rune) bool { return r < '0' || r > '9' }) {
			if n, err := strconv.Atoi(f); err == nil && n <= 65535 {
				out = append(out, uint16(n))
			}
		}
	}
	return out
}

func namesAgentPort(text string, ports []uint16) bool {
	for _, p := range portsIn(text) {
		for _, a := range ports {
			if a == p {
				return true
			}
		}
	}
	return false
}

func isScored(p uint16, scored []config.Port) bool {
	for _, s := range scored {
		if s.Port == p {
			return true
		}
	}
	return false
}

// blocks: the match text names a fleet address or an agent port, and no
// scored port. A rule that names a scored port is never a blocker, even
// beside a fleet address: it may be the very rule that guards the service.
func blocks(text string, fleet []netip.Prefix, ports []uint16, scored []config.Port) bool {
	for _, p := range portsIn(text) {
		if isScored(p, scored) {
			return false
		}
	}
	return namesFleet(text, fleet) || namesAgentPort(text, ports)
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
// other than ours (and the NAT and container tables), the drop and reject
// rules that name a fleet address or one of the agent's ports. A rule
// whose only matches are scored ports is never returned.
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
			skipT = skipTable(f[2])
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
			if blocks(rule, fleet, ports, scored) {
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
		// Words that are not addresses or ports cannot match: the comment
		// text is left out of the judgement.
		var judge []string
		for i := 0; i < len(f); i++ {
			if f[i] == "--comment" {
				i++
				continue
			}
			judge = append(judge, f[i])
		}
		text := strings.NewReplacer("--dports", "dports", "--dport", "dport", "--sports", "sports", "--sport", "sport").Replace(strings.Join(judge, " "))
		if !blocks(text, fleet, ports, scored) {
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

// DenyLines returns the lines of /etc/hosts.deny that name a fleet
// address, as they are written there. Comments and other lines are left.
func DenyLines(hostsDeny string, fleet []netip.Prefix) []string {
	var out []string
	for _, line := range strings.Split(hostsDeny, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, clients, _ := strings.Cut(line, ":")
		for _, tok := range strings.FieldsFunc(clients, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' }) {
			if denyNames(tok, fleet) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}
