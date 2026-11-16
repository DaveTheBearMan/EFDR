package agent

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xdr/internal/collect"
	"xdr/internal/proc"

	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/sshgate"
)

// assertSSH holds sshd's and PAM's config at their render. With report
// false, files it had to write are logged, not incidents. A baseline
// without either file keeps the gate off, said once.
func (a *agent) assertSSH(report bool) {
	changed, err := a.ssh.Assert(a.cfg, a.pol.Base, a.gateExe)
	for _, p := range changed {
		if report {
			a.record(incident.Incident{Kind: "ssh-drift", Action: "repaired", Severity: model.SevHigh, Detail: p + " restored"})
		} else {
			a.logf("ssh: wrote %s", p)
		}
	}
	if errors.Is(err, sshgate.ErrNoBase) {
		if !a.gateOffSaid {
			a.record(incident.Incident{Kind: "ssh-config", Action: "alert", Severity: model.SevCritical, Detail: err.Error()})
		}
		a.gateOffSaid = true
		return
	}
	a.gateOffSaid = false
	if err != nil {
		a.record(incident.Incident{Kind: "ssh-config", Action: "alert", Severity: model.SevCritical, Detail: err.Error()})
	}
}

// runCmd runs a command; its error carries what it printed.
func runCmd(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func outputCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// session is what the agent keeps of a live session.
type session struct {
	first time.Time // when it was first seen or registered
	said  bool      // its alert or pending incident was recorded
	ended bool      // its end was recorded
}

// gateOn reports whether sessions are judged: a gate is configured and its
// config could be rendered.
func (a *agent) gateOn() bool { return a.cfg.SSH != nil && a.ssh != nil && !a.gateOffSaid }

// paused reports whether a pause token holds now.
func (a *agent) paused() bool { return a.now().Before(a.pausedUntil) }

// sessions judges each logind session and acts on the verdicts; s is the
// sweep's snapshot, for the fallback kill of a session's leader.
func (a *agent) sessions(s *proc.Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.gateOn() {
		return
	}
	a.checkGrayUIDs()
	a.scanSpool()
	list, err := sshgate.Sessions(a.root)
	if err != nil {
		a.logf("sessions: %v", err)
		return
	}
	if a.sess == nil {
		a.sess = map[string]*session{}
	}
	now := a.now()
	p := sshgate.Policy{Cfg: a.cfg, BaseUsers: a.baseUsers(), Users: a.okUsers, Approved: a.approved, Killed: a.ended, Paused: a.paused(), Now: now}
	live := map[string]bool{}
	for _, ls := range list {
		live[ls.ID] = true
		st := a.sess[ls.ID]
		if st == nil {
			st = &session{first: now}
			a.sess[ls.ID] = st
		}
		v, why := sshgate.Judge(ls, st.first, p)
		in := incident.Incident{UID: ls.UID, User: ls.User, PID: ls.Leader, Detail: fmt.Sprintf("session %s from %s", ls.ID, ls.RemoteHost)}
		if why != "" {
			in.Detail += ": " + why
		}
		switch v {
		case sshgate.Alert:
			if !st.said {
				in.Kind, in.Action, in.Severity = "session", "alert", model.SevMedium
				if ls.User == a.cfg.SSH.Recovery || strings.HasPrefix(why, "user not in baseline") {
					in.Severity = model.SevHigh
				}
				a.record(in)
				st.said = true
			}
		case sshgate.Pending:
			if !st.said {
				in.Kind, in.Action, in.Severity = "session-pending", "alert", model.SevMedium
				a.record(in)
				st.said = true
			}
		case sshgate.End:
			if st.ended {
				continue
			}
			in.Kind, in.Action, in.Severity = "session-terminated", "killed", model.SevHigh
			if err := sshgate.Terminate(a.run, ls.ID); err != nil {
				in.Detail += "; loginctl: " + err.Error()
				if !a.killLeader(s, ls.Leader) {
					in.Action = "kill-failed"
				}
			}
			a.record(in)
			st.ended = true
		}
	}
	for id := range a.sess {
		if !live[id] {
			delete(a.sess, id)
		}
	}
}

// killLeader is the fallback when logind cannot end a session: its leader's
// process tree, scored services and the agent spared.
func (a *agent) killLeader(s *proc.Snapshot, pid int) bool {
	p := s.Procs[pid]
	if p == nil || pid <= 1 {
		return false
	}
	protect := func(q *proc.Proc) bool { return q.PID == a.pol.Self || a.pol.Guarded(s, q) }
	_, err := a.kill(pid, p.Start, protect)
	return err == nil
}

// baseUsers is the baseline's accounts by name.
func (a *agent) baseUsers() map[string]uint32 {
	m := map[string]uint32{}
	if a.pol.Base != nil {
		for _, acc := range a.pol.Base.Accounts {
			if !acc.Bad {
				m[acc.Name] = acc.UID
			}
		}
	}
	return m
}

// checkGrayUIDs reports a gray account whose uid is not its baseline uid,
// or is 0: once for each bad uid.
func (a *agent) checkGrayUIDs() {
	data, err := collect.ReadFile(filepath.Join(a.root, "etc/passwd"), 1<<20)
	if err != nil {
		return
	}
	base := a.baseUsers()
	if a.uidSaid == nil {
		a.uidSaid = map[string]uint32{}
	}
	for _, acc := range collect.ParsePasswd(strings.NewReader(string(data))) {
		if acc.Bad || !slices.Contains(a.cfg.GrayUsers, acc.Name) {
			continue
		}
		was, known := base[acc.Name]
		if acc.UID != 0 && (!known || acc.UID == was) {
			delete(a.uidSaid, acc.Name)
			continue
		}
		if said, ok := a.uidSaid[acc.Name]; ok && said == acc.UID {
			continue
		}
		a.uidSaid[acc.Name] = acc.UID
		a.record(incident.Incident{Kind: "account-uid", Action: "alert", Severity: model.SevCritical, UID: acc.UID, User: acc.Name,
			Detail: fmt.Sprintf("protected account %s has uid %d (baseline %d)", acc.Name, acc.UID, was)})
	}
}

// listenGate listens on the gate socket: a directory only root writes, a
// socket anyone may connect to.
func listenGate(sock string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		return nil, err
	}
	os.Remove(sock)
	l, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// onGate answers the gate socket: a session opening is registered (its
// grace starts now) and refused at once when the judge would end it; a
// token message is a break-glass use.
func (a *agent) onGate(m sshgate.Msg) sshgate.Reply {
	if m.Token != "" {
		return a.onToken(m)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.gateOn() {
		return sshgate.Reply{OK: true}
	}
	ls, ok := a.lookupSession(m)
	if !ok {
		return sshgate.Reply{Why: "session unknown to logind"}
	}
	if a.sess == nil {
		a.sess = map[string]*session{}
	}
	st := a.sess[ls.ID]
	if st == nil {
		st = &session{first: a.now()}
		a.sess[ls.ID] = st
	}
	p := sshgate.Policy{Cfg: a.cfg, BaseUsers: a.baseUsers(), Users: a.okUsers, Approved: a.approved, Killed: a.ended, Paused: a.paused(), Now: a.now()}
	if v, why := sshgate.Judge(ls, st.first, p); v == sshgate.End {
		st.ended = true
		a.record(incident.Incident{Kind: "session-refused", Action: "killed", Severity: model.SevHigh, UID: ls.UID, User: ls.User,
			Detail: fmt.Sprintf("session %s from %s: %s", ls.ID, ls.RemoteHost, why)})
		return sshgate.Reply{Why: why}
	}
	return sshgate.Reply{OK: true}
}

// lookupSession finds m's session: by its id, else by the cgroup of the
// process that ran the gate.
func (a *agent) lookupSession(m sshgate.Msg) (sshgate.Session, bool) {
	list, err := sshgate.Sessions(a.root)
	if err != nil {
		return sshgate.Session{}, false
	}
	id := m.Session
	if id == "" && m.PPID > 0 {
		cg, _ := collect.ReadFile(filepath.Join(a.root, "proc", strconv.Itoa(m.PPID), "cgroup"), 4096)
		id = sshgate.CgroupSession(cg)
	}
	for _, ls := range list {
		if id != "" && ls.ID == id {
			return ls, true
		}
	}
	return sshgate.Session{}, false
}
