package rules

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"xdr/internal/incident"
)

// maxDetail is the most bytes of an incident's detail a rule carries.
const maxDetail = 256

// FromIncident is the rules an incident proposes: the binary's hash
// unless it is a base-image binary, the remote endpoint, the parent that
// spawned a reverse shell, and the unit or crontab line that started it. Only
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
	if (in.Kind == "revshell-stdio" || in.Kind == "service-shell") && len(in.Chain) >= 2 && in.Chain[1].Exe != "" && in.Exe != "" {
		add(Rule{Kind: "parent", ParentExe: in.Chain[1].Exe, Exe: in.Exe})
	}
	if u, ok := strings.CutPrefix(in.Origin, "unit:"); ok && in.OriginSHA256 != "" {
		add(Rule{Kind: "unit", Unit: u, SHA256: in.OriginSHA256})
	}
	if in.Cron != "" {
		add(Rule{Kind: "cron", Command: in.Cron})
	}
	if e := in.Remote; e != nil && e.Port != 0 && (e.Proto == "tcp" || e.Proto == "udp") {
		if a, err := netip.ParseAddr(e.Addr); err == nil {
			add(Rule{Kind: "remote", Addr: a, Port: e.Port, Proto: e.Proto})
		}
	}
	return out
}

// maxExe is the most bytes of the path a hash rule names.
const maxExe = 512

// Bound cuts or refuses what a proposer controls beyond the match itself,
// so no proposal can bloat the signed set: Detail is cut, Seen is never
// later than now, and an over-long Exe is refused.
func (r *Rule) Bound(now time.Time) error {
	if len(r.Exe) > maxExe {
		return fmt.Errorf("exe of %d bytes", len(r.Exe))
	}
	r.Detail = cut(r.Detail, maxDetail)
	if r.Seen.IsZero() || r.Seen.After(now) {
		r.Seen = now
	}
	return nil
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
