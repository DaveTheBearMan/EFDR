package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/config"
	"xdr/internal/install"
	"xdr/internal/model"
	"xdr/internal/proc"
	"xdr/internal/sensor"
	"xdr/internal/tamper"
)

const (
	pinnedExe = "/usr/local/sbin/xdr"
	unitPath  = "/etc/systemd/system/xdr-agent.service"
)

func tamperRig(t *testing.T, procs ...*proc.Proc) (*rig, *[][]string) {
	r := newRig(t)
	r.snap = tree(procs...)
	r.a.snap = r.snap
	r.a.pinnedHash = func() string { return "sum:" + pinnedExe }
	r.a.copies = []string{pinnedExe, "/usr/lib/xdr/xdr", "/var/lib/xdr/bin/xdr"}
	var ran [][]string
	r.a.run = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	r.a.users[1000] = "mallory"
	r.a.cfg.SSH = &config.SSH{Blue: []string{"alice"}, Auto: []string{"root"}, Recovery: "xdrrecover"}
	return r, &ran
}

func hit(pid int) tamper.Event { return tamper.Event{PID: pid, Path: unitPath, Op: "modify"} }

func inSession(p *proc.Proc, id string) *proc.Proc {
	p.Cgroup = "0::/user.slice/user-1000.slice/session-" + id + ".scope"
	return p
}

func TestTamper_KillsActor(t *testing.T) {
	evil := inSession(mk(800, 1, 1000, "/tmp/evil"), "12")
	r, ran := tamperRig(t, evil)
	r.a.onTamper(hit(800))
	got := r.kind("tamper")
	if len(got) != 1 || got[0].Action != "killed" || got[0].Severity < 4 || got[0].PID != 800 || got[0].Path != unitPath || got[0].Exe != "/tmp/evil" {
		t.Fatalf("tamper: %+v", got)
	}
	if len(r.kills) != 1 || r.kills[0].pid != 800 {
		t.Fatalf("kills %+v", r.kills)
	}
	if terminates(*ran) != 1 || (*ran)[0][2] != "terminate-session" && (*ran)[0][1] != "terminate-session" {
		t.Fatalf("the session was not terminated: %v", *ran)
	}
}

func TestTamper_IgnoresOwnBinaries(t *testing.T) {
	agentP := mk(801, 1, 0, pinnedExe)
	chattr := mk(802, 801, 0, "/usr/bin/chattr") // run by ensure, which runs the pinned binary
	byHash := mk(803, 1, 0, "/opt/other/xdr")
	r, ran := tamperRig(t, agentP, chattr, byHash)
	r.a.pol.Hash = func(p *proc.Proc) string {
		if p.Exe == "/opt/other/xdr" {
			return "sum:" + pinnedExe // a copy with the pinned hash
		}
		return "sum:" + p.Exe
	}
	for _, pid := range []int{801, 802, 803, selfPID} {
		r.a.onTamper(hit(pid))
	}
	if len(r.got) != 0 || len(r.kills) != 0 || len(*ran) != 0 {
		t.Fatalf("the box's own work was taken for tamper: %+v kills %v", r.got, r.kills)
	}
}

// A short-lived helper (chattr, mv) is gone before the event is read: the
// sensor's exec events say whose child it was.
func TestTamper_ExecCacheIdentifiesAnExitedHelper(t *testing.T) {
	r, _ := tamperRig(t, mk(801, 1, 0, pinnedExe))
	r.a.noteExec(sensor.Event{Kind: sensor.Exec, PID: 810, PPID: 801, Filename: "/usr/bin/chattr"})
	r.a.onTamper(hit(810))
	if len(r.got) != 0 {
		t.Fatalf("an exited child of the agent was taken for tamper: %+v", r.got)
	}
	// Executing a pinned copy by path is the box's own, parent or not.
	r.a.noteExec(sensor.Event{Kind: sensor.Exec, PID: 811, PPID: 1, Filename: pinnedExe})
	r.a.noteExec(sensor.Event{Kind: sensor.Exec, PID: 812, PPID: 811, Filename: "/bin/sh"})
	r.a.onTamper(hit(812))
	if len(r.got) != 0 {
		t.Fatalf("a child of a run of the pinned binary: %+v", r.got)
	}
	// An exited stranger is reported and cannot be killed.
	r.a.noteExec(sensor.Event{Kind: sensor.Exec, PID: 820, PPID: 1, Filename: "/bin/sh"})
	r.a.onTamper(hit(820))
	if got := r.kind("tamper"); len(got) != 1 || got[0].Action != "alert" || len(r.kills) != 0 {
		t.Fatalf("%+v", got)
	}
	// And one nobody saw.
	r.a.onTamper(hit(999))
	if got := r.kind("tamper"); len(got) != 2 || got[1].Action != "alert" {
		t.Fatalf("%+v", got)
	}
}

func TestTamper_GrayAlertOnly(t *testing.T) {
	g := mk(830, 1, 2001, "/tmp/tool")
	r, _ := tamperRig(t, g)
	r.a.onTamper(hit(830))
	if got := r.kind("tamper"); len(got) != 1 || got[0].Action != "alert" || len(r.kills) != 0 {
		t.Fatalf("%+v kills %v", got, r.kills)
	}
}

func TestTamper_PausedAlertsOnly(t *testing.T) {
	r, ran := tamperRig(t, inSession(mk(800, 1, 1000, "/tmp/evil"), "12"))
	r.a.pausedUntil = r.now.Add(time.Hour)
	r.a.onTamper(hit(800))
	if got := r.kind("tamper"); len(got) != 1 || got[0].Action != "alert" || len(r.kills) != 0 || terminates(*ran) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestTamper_GuardedHeld(t *testing.T) {
	r, _ := tamperRig(t, mk(840, 1, 33, "/usr/sbin/apache2"))
	r.a.onTamper(hit(840))
	if got := r.kind("tamper"); len(got) != 1 || got[0].Action != "held" || len(r.kills) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestTamper_AutoSessionNotTerminated(t *testing.T) {
	op := inSession(mk(850, 1, 0, "/tmp/tool"), "13") // root: an auto account
	r, ran := tamperRig(t, op)
	r.a.onTamper(hit(850))
	if len(r.kills) != 1 || terminates(*ran) != 0 {
		t.Fatalf("kills %v, terminated %v", r.kills, *ran)
	}
}

func TestTamper_BurstIsOneIncident(t *testing.T) {
	r, _ := tamperRig(t, mk(860, 1, 1000, "/tmp/evil"))
	for i := 0; i < 5; i++ {
		r.a.onTamper(hit(860))
	}
	if n := len(r.kind("tamper")); n != 1 || len(r.kills) != 1 {
		t.Fatalf("%d incidents, %d kills", n, len(r.kills))
	}
	// Two seconds later it is a new event (the incident log may fold the
	// identical line; the agent acts again).
	r.now = r.now.Add(2 * time.Second)
	r.a.onTamper(hit(860))
	if len(r.kills) != 2 {
		t.Fatalf("a repeat two seconds later: %d kills", len(r.kills))
	}
}

// What ensure put back or started is a tamper incident: something removed,
// changed or stopped it.
func TestTamper_EnsureNotesAreReported(t *testing.T) {
	r, _ := tamperRig(t)
	l := install.DefaultLayout()
	l.Root = t.TempDir()
	run := func(string, ...string) ([]byte, error) { return []byte("active\n"), nil }
	cfg := filepath.Join(l.Root, l.Config)
	os.MkdirAll(filepath.Dir(cfg), 0o755)
	os.WriteFile(cfg, []byte("{}\n"), 0o600)
	bin := filepath.Join(t.TempDir(), "xdr")
	os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
	if _, err := install.Install(l, run, bin); err != nil {
		t.Fatal(err)
	}
	r.a.layout, r.a.runner = l, run
	r.a.ensureNotes()
	if got := r.kind("tamper"); len(got) != 0 {
		t.Fatalf("nothing was done, yet %+v", got)
	}
	copy3 := l.Copies[2]
	os.WriteFile(filepath.Join(l.Root, copy3), []byte("corrupt"), 0o755)
	if _, err := install.Ensure(l, run); err != nil {
		t.Fatal(err)
	}
	r.a.ensureNotes()
	got := r.kind("tamper")
	if len(got) != 1 || got[0].Path != copy3 || got[0].Action != "repaired" || got[0].Severity != model.SevHigh ||
		!strings.Contains(got[0].Detail, "ensure restored "+copy3) {
		t.Fatalf("tamper: %+v", got)
	}
	r.a.ensureNotes()
	if n := len(r.kind("tamper")); n != 1 {
		t.Fatalf("reported again: %d", n)
	}
}
