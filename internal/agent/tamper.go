package agent

import (
	"context"
	"encoding/json"
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
	procGap    = 250 * time.Millisecond // at most one full /proc read per this, for tamper events
	dropsGap   = time.Minute            // at most one alert of lost tamper events per this
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
//
// A writer the event's pidfd shows exited (or the kernel said had) is never
// taken from /proc by its pid: the pid may be another process's by now.
// It is an alert, unless the chain says it was the box's own.
func (a *agent) onTamper(ev tamper.Event) {
	defer ev.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.uninstalled {
		return // its own uninstall removing the files
	}
	pid := ev.PID
	if pid <= 0 || pid == a.pol.Self {
		return
	}
	now := a.now()
	key := fmt.Sprintf("%d|%s", pid, ev.Path)
	if t, ok := a.tamperSeen[key]; ok && now.Sub(t) < tamperGap {
		return
	}
	// A pid the snapshot lacks costs a full /proc read, at most every
	// procGap: a flood of events must not become a flood of reads. One in
	// between is judged on what is known (the exec cache) and, its process
	// unseen, is an alert with the event's pid.
	snap := a.snap
	if (snap == nil || snap.Procs[pid] == nil) && now.Sub(a.tamperRead) >= procGap {
		a.tamperRead = now
		if s, err := a.read(); err == nil && s != nil {
			snap = s
		}
	}
	if snap == nil {
		snap = &proc.Snapshot{}
	}
	// Looked at after the read: a pidfd that shows the writer alive now
	// means the pid in /proc is still the writer's.
	gone := ev.Gone()
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
			if hops == 0 && !gone {
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
		protect := func(p *proc.Proc) bool { return p.PID == a.pol.Self || a.pol.Guarded(snap, p) }
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
	a.tamperDropped = w.Dropped
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

// ensureNotes reports what the launch points' ensure had to do since the
// last look, one tamper incident per run: a file put back or a unit started
// means something removed, changed or stopped it.
func (a *agent) ensureNotes() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.runner == nil {
		return // not the installed agent
	}
	for _, n := range install.TakeNotes(a.layout) {
		var did []string
		if len(n.Restored) > 0 {
			did = append(did, "restored "+strings.Join(n.Restored, ", "))
		}
		if len(n.Started) > 0 {
			did = append(did, "started "+strings.Join(n.Started, ", "))
		}
		in := incident.Incident{Kind: "tamper", Action: "repaired", Severity: model.SevHigh, Time: n.Time,
			Detail: "ensure " + strings.Join(did, "; ")}
		if len(n.Restored) > 0 {
			in.Path = n.Restored[0]
		}
		if n.Error != "" {
			in.Action, in.Severity = "alert", model.SevCritical
			if len(did) == 0 {
				in.Detail = "ensure"
			}
			in.Detail += ": " + n.Error
		}
		a.record(in)
	}
}

// keepPinned puts back the pinned hash and the manifest when both copies of
// either are gone: ensure has nothing to restore them from, and without
// them every launch point stands down. The hash is the manifest's for the
// copies (what install pinned), else the agent's own. A box marked
// uninstalled by anything but this agent's own uninstall is reported, once,
// and left: the CLI's uninstall may be at work.
func (a *agent) keepPinned() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.runner == nil || a.uninstalled || a.uninstTried {
		return
	}
	l := a.layout
	if b, err := install.ReadManifestBytes(l); err == nil {
		a.manifest = b
	}
	if install.Uninstalled(l) {
		if !a.markerSaid {
			a.markerSaid = true
			a.record(incident.Incident{Kind: "tamper", Action: "alert", Severity: model.SevHigh, Path: l.Uninstalled,
				Detail: "the box is marked uninstalled while the agent runs: ensure and the guards stand down"})
		}
		return
	}
	a.markerSaid = false
	hash := a.selfHash
	var m install.Manifest
	if a.manifest != nil && json.Unmarshal(a.manifest, &m) == nil {
		for _, e := range m.Entries {
			if e.Kind == "copy" && e.SHA256 != "" {
				hash = e.SHA256
				break
			}
		}
	}
	wrote, err := install.Repin(l, a.runner, hash, a.manifest)
	if len(wrote) == 0 && err == nil {
		return
	}
	in := incident.Incident{Kind: "tamper", Action: "repaired", Severity: model.SevHigh,
		Detail: "the pinned hash or the manifest was gone, both copies: the agent rewrote " + strings.Join(wrote, ", ")}
	if len(wrote) > 0 {
		in.Path = wrote[0]
	}
	if err != nil {
		in.Action, in.Severity, in.Detail = "alert", model.SevCritical, in.Detail+": "+err.Error()
	}
	a.record(in)
}

// tamperDrops reports the tamper events the watcher lost (the kernel's queue
// overflowed, or the agent fell behind), at most one alert per dropsGap:
// what they were is not known, only that changes went unseen.
func (a *agent) tamperDrops() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tamperDropped == nil || a.uninstalled {
		return
	}
	n := a.tamperDropped()
	now := a.now()
	if n <= a.dropsSeen || !a.dropsSaid.IsZero() && now.Sub(a.dropsSaid) < dropsGap {
		return
	}
	a.record(incident.Incident{Kind: "tamper", Action: "alert", Severity: model.SevHigh,
		Detail: fmt.Sprintf("%d tamper events lost (fanotify queue overflow or a flood): changes to the installed files went unseen", n-a.dropsSeen)})
	a.dropsSeen, a.dropsSaid = n, now
}
