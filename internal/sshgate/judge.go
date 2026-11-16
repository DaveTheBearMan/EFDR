package sshgate

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"xdr/internal/config"
)

// Verdict is what the gate does with a session.
type Verdict int

const (
	Keep    Verdict = iota
	Alert           // keep, and say so once
	Pending         // inside the grace, not yet approved
	End             // end it (Terminate is the function that does)
)

func (v Verdict) String() string {
	return [...]string{"keep", "alert", "pending", "end"}[v]
}

// Policy is what a verdict depends on besides the session.
type Policy struct {
	Cfg       *config.Config
	BaseUsers map[string]uint32 // the baseline's accounts
	Users     map[string]bool   // accounts approved since
	Approved  map[string]bool   // session ids approved
	Killed    map[string]bool   // session ids ordered ended
	Paused    bool              // a pause token holds
	Now       time.Time
}

// Judge rules on session s, first seen at first. Only sshd sessions are
// judged. The first rule that matches wins; a gray account is never ended.
func Judge(s Session, first time.Time, p Policy) (Verdict, string) {
	if s.Service != "sshd" {
		return Keep, ""
	}
	ssh := p.Cfg.SSH
	from := s.RemoteHost
	switch {
	case slices.Contains(p.Cfg.GrayUsers, s.User):
		return Alert, "gray login from " + from
	case ssh.Recovery != "" && s.User == ssh.Recovery:
		return Alert, "recovery login from " + from
	case p.Killed[s.ID]:
		return End, "killed by order"
	case slices.Contains(ssh.Auto, s.User) && inNets(p.Cfg.Jump, s.RemoteAddr):
		return Keep, ""
	}
	if _, ok := p.BaseUsers[s.User]; !ok && !p.Users[s.User] && !slices.Contains(ssh.Auto, s.User) {
		if p.Paused {
			return Alert, "user not in baseline, from " + from + " (paused)"
		}
		return End, "user not in baseline, from " + from
	}
	switch {
	case p.Approved[s.ID]:
		return Keep, ""
	case p.Paused:
		return Keep, "paused"
	case p.Now.Sub(first) < ssh.Grace.Duration:
		return Pending, ""
	}
	return End, fmt.Sprintf("not approved within %s", ssh.Grace.Duration)
}

func inNets(nets []config.Net, a netip.Addr) bool {
	return a.IsValid() && slices.ContainsFunc(nets, func(n config.Net) bool { return n.Contains(a) })
}
