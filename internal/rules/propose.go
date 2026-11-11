package rules

import (
	"net/netip"
	"unicode/utf8"

	"xdr/internal/incident"
)

// maxDetail is the most bytes of an incident's detail a rule carries.
const maxDetail = 256

// FromIncident is the rules an incident proposes: the binary's hash
// unless it is a base-image binary, and the remote endpoint. Only
// reverse shells and blocked egress the agent acted on, or would have,
// propose anything.
func FromIncident(in incident.Incident, baselineExe bool) []Rule {
	switch in.Kind {
	case "revshell-stdio", "service-shell", "egress":
	default:
		return nil
	}
	switch in.Action {
	case "killed", "would-kill", "held":
	default:
		return nil
	}
	detail := cut(in.Kind+": "+in.Detail, maxDetail)
	var out []Rule
	add := func(r Rule) {
		r.From, r.Seen, r.Detail = in.Host, in.Time, detail
		r.SetID()
		out = append(out, r)
	}
	if in.SHA256 != "" && !baselineExe {
		add(Rule{Kind: "hash", SHA256: in.SHA256, Exe: in.Exe})
	}
	if e := in.Remote; e != nil && e.Port != 0 && (e.Proto == "tcp" || e.Proto == "udp") {
		if a, err := netip.ParseAddr(e.Addr); err == nil {
			add(Rule{Kind: "remote", Addr: a, Port: e.Port, Proto: e.Proto})
		}
	}
	return out
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
