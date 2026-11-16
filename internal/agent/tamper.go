package agent

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"xdr/internal/incident"
	"xdr/internal/install"
	"xdr/internal/model"
	"xdr/internal/proc"
	"xdr/internal/sensor"
	"xdr/internal/sshgate"
	"xdr/internal/tamper"
)

const (
	maxExecs   = 4096
	execKeep   = 2 * time.Minute
	tamperGap  = time.Second
	maxChain   = 16
	maxSeenKey = 256
)

// execInfo is what the sensor saw of a process starting.
type execInfo struct {
	PPID int
	File string
	At   time.Time
}

// noteExec remembers a process start, for a writer that has exited by the
// time its change is read (chattr, mv, rm).
func (a *agent) noteExec(ev sensor.Event) {
	if ev.Kind != sensor.Exec {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.execs == nil {
		a.execs = map[int]execInfo{}
	}
	now := a.now()
	if len(a.execs) >= maxExecs {
		for pid, e := range a.execs {
			if now.Sub(e.At) > execKeep {
				delete(a.execs, pid)
			}
		}
		if len(a.execs) >= maxExecs {
			a.execs = map[int]execInfo{}
		}
	}
	a.execs[ev.PID] = execInfo{PPID: ev.PPID, File: ev.Filename, At: now}
}

// ownExe reports whether a process running exe (with that hash) is the
// box's own XDR: one of the installed copies, or anything with the pinned
// hash.
func (a *agent) ownExe(exe, hash string) bool {
	if exe != "" && slices.Contains(a.copies, exe) {
		return true
	}
	return hash != "" && a.pinnedHash != nil && hash == a.pinnedHash()
}

// onTamper deals with a change to an installed file. The process that
// made it is the box's own (the agent, a guard, ensure, or anything they
// started) or it is red team: a Critical incident either way is wrong for
// the first, so nothing is said for it. For the second the process tree is
// killed, and its login session ended, by the same rules as every kill: a
// gray account and a pause token make it an alert, a scored service is held,
// the box's own auto and recovery accounts keep their session.
func (a *agent) onTamper(ev tamper.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	pid := ev.PID
	if pid <= 0 || pid == a.pol.Self {
		return
	}
	now := a.now()
	key := fmt.Sprintf("%d|%s", pid, ev.Path)
	if t, ok := a.tamperSeen[key]; ok && now.Sub(t) < tamperGap {
		return
	}
	snap := a.snap
	if snap == nil || snap.Procs[pid] == nil {
		if s, err := a.read(); err == nil && s != nil {
			snap = s
		}
	}
	var actor *proc.Proc
	known := false
	for cur, hops := pid, 0; cur > 1 && hops < maxChain; hops++ {
		var exe, hash string
		var next int
		if p := snap.Procs[cur]; p != nil {
			exe, next = p.Exe, p.PPID
			if a.pol.Hash != nil {
				hash = a.pol.Hash(p)
			}
			if hops == 0 {
				actor, known = p, true
			}
		} else if e, ok := a.execs[cur]; ok {
			exe, next = e.File, e.PPID
			known = known || hops == 0
		} else {
			break
		}
		if a.ownExe(exe, hash) {
			return
		}
		cur = next
	}
	if a.tamperSeen == nil || len(a.tamperSeen) >= maxSeenKey {
		a.tamperSeen = map[string]time.Time{}
	}
	a.tamperSeen[key] = now
	in := incident.Incident{Kind: "tamper", Severity: model.SevCritical, PID: pid, Path: ev.Path,
		Detail: fmt.Sprintf("%s of %s by pid %d", ev.Op, ev.Path, pid)}
	if actor == nil {
		in.Action = "alert"
		if known {
			in.Detail += " (the process had exited; the sensor saw it start)"
		} else {
			in.Detail += " (the process had already exited)"
		}
		a.record(in)
		return
	}
	in.Exe, in.UID, in.User = actor.Exe, actor.UID, a.users[actor.UID]
	if a.pol.Hash != nil {
		in.SHA256 = a.pol.Hash(actor)
	}
	var session string
	switch {
	case a.paused():
		in.Action = "alert"
	case a.pol.IsGray(snap, actor):
		in.Action = "alert"
	case a.pol.Guarded(snap, actor):
		in.Action = "held"
	default:
		session = sshgate.CgroupSession([]byte(actor.Cgroup))
		protect := func(p *proc.Proc) bool { return p.PID == a.pol.Self }
		if _, err := a.kill(pid, actor.Start, protect); err != nil {
			in.Action, in.Detail = "kill-failed", in.Detail+": "+err.Error()
		} else {
			in.Action = "killed"
		}
	}
	a.record(in)
	if in.Action != "killed" || session == "" || a.run == nil {
		return
	}
	user := a.users[actor.UID]
	if s := a.cfg.SSH; s != nil && (slices.Contains(s.Auto, user) || user == s.Recovery) || slices.Contains(a.cfg.GrayUsers, user) {
		return
	}
	end := incident.Incident{Kind: "session-terminated", Action: "killed", Severity: model.SevHigh, UID: actor.UID, User: user,
		Detail: "session " + session + ": its process tampered with XDR's files"}
	if err := sshgate.Terminate(a.run, session); err != nil {
		end.Action, end.Detail = "kill-failed", end.Detail+": "+err.Error()
	}
	a.record(end)
}

// startTamper watches the installed files when this box has an install.
func (a *agent) startTamper(ctx context.Context) {
	l := install.DefaultLayout()
	m, err := install.ReadManifest(l)
	if err != nil {
		return // not installed: nothing to protect
	}
	paths := []string{l.Manifest, l.Pinned, l.Backup + "/manifest.json", l.Backup + "/pinned.sha256"}
	for _, e := range m.Entries {
		paths = append(paths, e.Path)
	}
	w, err := tamper.Watch(paths, []string{"/usr/lib/xdr", "/var/lib/xdr/bin", l.Backup, l.FleetDir})
	if err != nil {
		a.recordLocked(incident.Incident{Kind: "tamper", Action: "alert", Severity: model.SevHigh, Detail: "not watching the installed files: " + err.Error()})
		return
	}
	if n := w.Skipped(); n > 0 {
		a.logf("tamper: %d directories could not be watched", n)
	}
	go func() { <-ctx.Done(); w.Close() }()
	go func() {
		for ev := range w.Events() {
			a.onTamper(ev)
		}
	}()
}

func readPinned() string {
	b, _ := os.ReadFile(install.DefaultLayout().Pinned)
	return strings.TrimSpace(string(b))
}
