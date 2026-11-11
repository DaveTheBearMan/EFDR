// Package detect turns a process snapshot, or one sensor event, into
// detections. It reads nothing and changes nothing.
package detect

import (
	"net/netip"
	"slices"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/pathenc"
	"xdr/internal/proc"
	"xdr/internal/rules"
)

// Policy is what the detectors judge against.
type Policy struct {
	Cfg   *config.Config
	Base  *baseline.Baseline      // composed layers; nil: nothing is baseline
	Gray  map[uint32]bool         // uids of cfg.GrayUsers
	Self  int                     // the agent's pid
	Local func(netip.Addr) bool   // an address of this host
	Hash  func(*proc.Proc) string // "" on error
	Rules *rules.Index            // the fleet's signed rules; nil: none
}

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

func within(nets []config.Net, a netip.Addr) bool {
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// AllowedOut reports whether a process may send to dst. It mirrors the
// output chain of the firewall, except for the resolver: that is for the
// stub alone.
func (p *Policy) AllowedOut(dst netip.AddrPort, proto string) bool {
	a, port := dst.Addr().Unmap(), dst.Port()
	switch {
	case a.IsLoopback(), a.IsMulticast(), a == broadcast:
		return true
	case p.Local != nil && p.Local(a):
		return true
	case proto == "tcp" && slices.Contains(p.Cfg.XDRPorts, port) && (within(p.Cfg.Jump, a) || within(p.Cfg.Peers, a)):
		return true
	case p.Cfg.DHCP && proto == "udp" && port == 67:
		return true
	}
	for _, d := range p.Cfg.AllowOut {
		if d.Proto == proto && d.Port == port && d.To.Contains(a) {
			return true
		}
	}
	return false
}

// Baseline reports whether pr runs a binary of the base image, unchanged.
func (p *Policy) Baseline(pr *proc.Proc) bool {
	if p.Base == nil || pr.Exe == "" || pr.ExeDeleted || proc.Container(pr.Cgroup) != "" {
		return false
	}
	e, ok := p.Base.Files[pathenc.Encode(pr.Exe)]
	return ok && e.SHA256 != "" && p.Hash != nil && p.Hash(pr) == e.SHA256
}

// Guarded reports whether pr is, or stands in for, a scored service: its
// binary is a guard_exes entry, or it holds a listening socket on a
// scored port.
func (p *Policy) Guarded(s *proc.Snapshot, pr *proc.Proc) bool {
	if slices.Contains(p.Cfg.GuardExes, pr.Exe) {
		return true
	}
	for _, k := range s.Sockets(pr) {
		if k.Listen && inet(k.Sock) && p.scored(k.Proto, k.Local.Port()) {
			return true
		}
	}
	return false
}

func (p *Policy) scored(proto string, port uint16) bool {
	return slices.Contains(p.Cfg.Scored, config.Port{Proto: proto, Port: port})
}

// IsGray reports whether pr, or anything it descends from, runs as a
// gray-team account.
func (p *Policy) IsGray(s *proc.Snapshot, pr *proc.Proc) bool {
	if p.Gray[pr.UID] {
		return true
	}
	for _, a := range s.Chain(pr.PID) {
		if p.Gray[a.UID] {
			return true
		}
	}
	return false
}

// Class sorts a process by what it runs: "shell", "interp", "nettool" or
// "". See proc.Class.
func Class(pr *proc.Proc) string { return proc.Class(pr.Exe, pr.Comm) }
