package detect

import (
	"cmp"
	"fmt"
	"net/netip"
	"path"
	"slices"

	"golang.org/x/sys/unix"

	"xdr/internal/config"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/proc"
	"xdr/internal/rules"
	"xdr/internal/sensor"
)

// Detection is one thing found on one process.
type Detection struct {
	Kind     string // revshell-stdio | service-shell | egress | dns | rawsock | listener | rule-hash | rule-remote
	PID      int
	Start    uint64 // 0: the process was gone when it was judged
	Severity model.Severity
	Remote   *incident.Endpoint
	Detail   string
	NoKill   bool
}

const exited = " (exited)"

func inet(k proc.Sock) bool { return k.Family == unix.AF_INET || k.Family == unix.AF_INET6 }

// connected reports whether a tcp or udp socket has a peer.
func connected(k proc.Sock) bool {
	return inet(k) && (k.Proto == "tcp" || k.Proto == "udp") && !k.Listen &&
		k.Remote.IsValid() && k.Remote.Port() != 0 && !k.Remote.Addr().IsUnspecified()
}

func endpoint(a netip.AddrPort, proto string) *incident.Endpoint {
	return &incident.Endpoint{Addr: a.Addr().Unmap().String(), Port: a.Port(), Proto: proto}
}

func name(pr *proc.Proc) string {
	if pr.Exe != "" {
		return path.Base(pr.Exe)
	}
	return pr.Comm
}

func isSSHD(pr *proc.Proc) bool {
	n := name(pr)
	return n == "sshd" || n == "sshd-session"
}

func (p *Policy) subject(pr *proc.Proc) bool { return pr.PID != p.Self && !pr.Kernel }

// revshell reports a shell or interpreter whose stdin, stdout or stderr
// is a connection.
func revshell(cls string, s *proc.Snapshot, pr *proc.Proc) []Detection {
	if cls != "shell" && cls != "interp" {
		return nil
	}
	for _, k := range s.Sockets(pr) {
		if k.FD > 2 {
			break
		}
		if connected(k.Sock) {
			return []Detection{{Kind: "revshell-stdio", PID: pr.PID, Start: pr.Start, Severity: model.SevCritical,
				Remote: endpoint(k.Remote, k.Proto),
				Detail: fmt.Sprintf("fd %d is a %s connection to %s", k.FD, k.Proto, k.Remote)}}
		}
	}
	return nil
}

// service finds the scored service a shell was started under: the nearest
// ancestor that is guarded and listens. Init is no service (with socket
// activation it holds every unit's listener, and everything descends from
// it), nor is sshd, and a shell under a shell is its parent's affair.
func (p *Policy) service(s *proc.Snapshot, ancestors []*proc.Proc) *proc.Proc {
	for _, a := range ancestors {
		if a.PID == 1 || a.Kernel {
			return nil
		}
		if c := Class(a); c == "shell" || c == "nettool" {
			return nil
		}
		if isSSHD(a) || !p.Guarded(s, a) {
			continue
		}
		for _, k := range s.Sockets(a) {
			if k.Listen && inet(k.Sock) {
				return a
			}
		}
	}
	return nil
}

func (p *Policy) serviceShell(cls string, s *proc.Snapshot, ancestors []*proc.Proc) (string, bool) {
	if cls != "shell" && cls != "nettool" {
		return "", false
	}
	svc := p.service(s, ancestors)
	if svc == nil {
		return "", false
	}
	return fmt.Sprintf("started under %s (pid %d)", name(svc), svc.PID), true
}

// egress names a destination a process may not reach: "dns" for a name
// server, "egress" for anything else, "" when it is allowed.
func (p *Policy) egress(dst netip.AddrPort, proto string) (kind, detail string) {
	if !dst.IsValid() || dst.Addr().IsUnspecified() || p.AllowedOut(dst, proto) {
		return "", ""
	}
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	if dst.Port() == 53 || dst.Port() == 853 {
		return "dns", fmt.Sprintf("%s to name server %s, past the stub", proto, dst)
	}
	return "egress", fmt.Sprintf("%s to %s is not allowed out", proto, dst)
}

// listening is the tcp ports with a listener, per network namespace.
func listening(s *proc.Snapshot) map[string]map[uint16]bool {
	out := map[string]map[uint16]bool{}
	for ns, socks := range s.Socks {
		out[ns] = map[uint16]bool{}
		for _, k := range socks {
			if k.Proto == "tcp" && k.Listen {
				out[ns][k.Local.Port()] = true
			}
		}
	}
	return out
}

// listeners finds the sockets that listen where nothing should, each
// reported on the topmost process holding it.
func (p *Policy) listeners(s *proc.Snapshot, pids []int) map[int][]Detection {
	type key struct {
		ns    string
		inode uint64
	}
	holders := map[key][]*proc.Proc{}
	socks := map[key]proc.Sock{}
	for _, pid := range pids {
		pr := s.Procs[pid]
		for _, k := range s.Sockets(pr) {
			id := key{pr.NetNS, k.Inode}
			if !inet(k.Sock) || !k.Listen || k.Local.Port() == 0 {
				continue
			}
			if k.Proto != "tcp" && (k.Proto != "udp" || k.Local.Port() >= 32768) {
				continue
			}
			if h := holders[id]; len(h) == 0 || h[len(h)-1] != pr {
				holders[id] = append(h, pr)
			}
			socks[id] = k.Sock
		}
	}
	out := map[int][]Detection{}
	for id, hs := range holders {
		k := socks[id]
		if p.scored(k.Proto, k.Local.Port()) || slices.ContainsFunc(hs, func(h *proc.Proc) bool { return p.knownListener(k, h) }) {
			continue
		}
		top := hs[0]
		for _, h := range hs {
			if !slices.ContainsFunc(hs, func(o *proc.Proc) bool { return o.PID == h.PPID }) {
				top = h
				break
			}
		}
		d := Detection{Kind: "listener", PID: top.PID, Start: top.Start, Severity: model.SevHigh,
			Detail: fmt.Sprintf("listens on %s %s, which is not a known listener", k.Proto, k.Local)}
		if k.Local.Addr().IsLoopback() {
			d.Severity, d.NoKill = model.SevLow, true
		}
		out[top.PID] = append(out[top.PID], d)
	}
	for _, ds := range out {
		slices.SortFunc(ds, func(a, b Detection) int { return cmp.Compare(a.Detail, b.Detail) })
	}
	return out
}

func (p *Policy) knownListener(k proc.Sock, holder *proc.Proc) bool {
	if name(holder) == "docker-proxy" {
		return true
	}
	return slices.ContainsFunc(p.Cfg.Listeners, func(l config.Listener) bool {
		return l.Proto == k.Proto && l.Port == k.Local.Port() && l.Exe == holder.Exe
	})
}

// knownRaw reports whether holder may hold a socket of kind raw ("packet"
// or "raw"): a listeners entry names that kind and its path, and the
// binary is the one the baseline has.
func (p *Policy) knownRaw(raw string, holder *proc.Proc) bool {
	return holder != nil && p.Baseline(holder) && slices.ContainsFunc(p.Cfg.Listeners, func(l config.Listener) bool {
		return l.Proto == raw && l.Exe == holder.Exe
	})
}

func ruleHit(kind string, pid int, start uint64, r *rules.Rule, remote *incident.Endpoint) Detection {
	return Detection{Kind: kind, PID: pid, Start: start, Severity: model.SevCritical, Remote: remote,
		Detail: "rule " + r.ID + " from " + r.From + ": " + r.Detail}
}

// ruleHash is the hash rule pr's binary hits, or nil.
func (p *Policy) ruleHash(pr *proc.Proc) *rules.Rule {
	if p.Rules == nil || len(p.Rules.Hash) == 0 || p.Hash == nil {
		return nil
	}
	sum := p.Hash(pr)
	if sum == "" {
		return nil
	}
	return p.Rules.Hash[sum]
}

// ruleRemote is the remote rule a connection to dst hits, or nil.
func (p *Policy) ruleRemote(dst netip.AddrPort, proto string) *rules.Rule {
	if p.Rules == nil {
		return nil
	}
	return p.Rules.Remote[rules.RemoteKey{Addr: dst.Addr().Unmap(), Port: dst.Port(), Proto: proto}]
}

// Sweep judges every process in the snapshot. Detections come ordered by
// pid.
func Sweep(s *proc.Snapshot, p *Policy) []Detection {
	var pids []int
	for pid, pr := range s.Procs {
		if p.subject(pr) {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	listens := listening(s)
	unknown := p.listeners(s, pids)

	var out []Detection
	for _, pid := range pids {
		pr := s.Procs[pid]
		cls := Class(pr)
		out = append(out, revshell(cls, s, pr)...)
		if detail, ok := p.serviceShell(cls, s, s.Chain(pid)[1:]); ok {
			out = append(out, Detection{Kind: "service-shell", PID: pid, Start: pr.Start, Severity: model.SevHigh, Detail: detail})
		}
		if r := p.ruleHash(pr); r != nil {
			out = append(out, ruleHit("rule-hash", pid, pr.Start, r, nil))
		}
		seen := map[string]bool{}
		raw := ""
		for _, k := range s.Sockets(pr) {
			switch {
			case k.Family == unix.AF_PACKET:
				raw = "packet"
			case k.Proto == "raw" && raw == "":
				raw = "raw"
			}
			if !connected(k.Sock) {
				continue
			}
			// A connection to a scored port is the scorer's or an
			// attacker's alike: no rule cuts it.
			if r := p.ruleRemote(k.Remote, k.Proto); r != nil && !p.scored(k.Proto, k.Local.Port()) && !seen["rule "+r.ID] {
				seen["rule "+r.ID] = true
				out = append(out, ruleHit("rule-remote", pid, pr.Start, r, endpoint(k.Remote, k.Proto)))
			}
			if k.Proto == "tcp" && !k.SynSent && listens[pr.NetNS][k.Local.Port()] {
				continue
			}
			kind, detail := p.egress(k.Remote, k.Proto)
			if kind == "" || seen[detail] {
				continue
			}
			seen[detail] = true
			out = append(out, Detection{Kind: kind, PID: pid, Start: pr.Start, Severity: model.SevHigh, Remote: endpoint(k.Remote, k.Proto), Detail: detail})
		}
		if raw != "" && !p.knownRaw(raw, pr) {
			out = append(out, Detection{Kind: "rawsock", PID: pid, Start: pr.Start, Severity: model.SevHigh, Detail: "holds a " + raw + " socket"})
		}
		out = append(out, unknown[pid]...)
	}
	return out
}

// Event judges one sensor event against the snapshot. A process that is
// no longer there is still reported, with Start 0.
func Event(ev sensor.Event, s *proc.Snapshot, p *Policy) []Detection {
	pr := s.Procs[ev.PID]
	if ev.PID == p.Self || pr != nil && !p.subject(pr) {
		return nil
	}
	d := Detection{PID: ev.PID, Severity: model.SevHigh}
	suffix := exited
	if pr != nil {
		d.Start, suffix = pr.Start, ""
	}
	switch ev.Kind {
	case sensor.Connect, sensor.Send:
		var out []Detection
		if r := p.ruleRemote(ev.Dst, ev.Proto); r != nil {
			hit := ruleHit("rule-remote", ev.PID, d.Start, r, endpoint(ev.Dst, ev.Proto))
			hit.Detail += suffix
			out = append(out, hit)
		}
		kind, detail := p.egress(ev.Dst, ev.Proto)
		if kind == "" {
			return out
		}
		d.Kind, d.Detail, d.Remote = kind, detail+suffix, endpoint(ev.Dst, ev.Proto)
		return append(out, d)
	case sensor.Socket:
		raw := ""
		switch {
		case ev.Family == unix.AF_PACKET:
			raw = "packet"
		case (ev.Family == unix.AF_INET || ev.Family == unix.AF_INET6) && ev.SockType&0xf == unix.SOCK_RAW:
			raw = "raw"
		default:
			return nil
		}
		if p.knownRaw(raw, pr) {
			return nil
		}
		d.Detail = "opened a " + raw + " socket"
		d.Kind, d.Detail = "rawsock", d.Detail+suffix
		return []Detection{d}
	case sensor.Exec:
		// The exec is judged by what was executed: by now the pid may run
		// something else, or nothing.
		cls := class(ev.Filename, ev.Comm)
		var out []Detection
		var ancestors []*proc.Proc
		if pr != nil {
			out = revshell(cls, s, pr)
			if r := p.ruleHash(pr); r != nil {
				out = append(out, ruleHit("rule-hash", ev.PID, pr.Start, r, nil))
			}
			ancestors = s.Chain(ev.PID)[1:]
		} else if ev.PPID != 0 {
			ancestors = s.Chain(ev.PPID)
		}
		if detail, ok := p.serviceShell(cls, s, ancestors); ok {
			d.Kind, d.Detail = "service-shell", execName(ev)+" "+detail+suffix
			out = append(out, d)
		}
		return out
	}
	return nil
}

func execName(ev sensor.Event) string {
	if ev.Filename != "" {
		return path.Base(ev.Filename)
	}
	return ev.Comm
}
