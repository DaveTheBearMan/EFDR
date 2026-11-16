package agent

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/detect"
	"xdr/internal/dnsguard"
	"xdr/internal/install"
	"xdr/internal/model"
	"xdr/internal/sshgate"
	"xdr/internal/testfs"
)

func tokenRig(t *testing.T) (*rig, ed25519.PrivateKey) {
	r, _ := gateOn(t)
	pub, key, _ := ed25519.GenerateKey(nil)
	r.a.tokenPub = pub
	r.a.state = filepath.Join(r.root, "var/lib/xdr")
	r.a.spool = filepath.Join(r.root, "var/lib/xdr/breakglass")
	return r, key
}

func mint(r *rig, key ed25519.PrivateKey, id, action string) string {
	return breakglass.Mint(breakglass.Token{V: 1, ID: id, Host: "web01", Action: action, NotBefore: r.now.Add(-time.Minute), Expires: r.now.Add(2 * time.Hour)}, key)
}

func TestBreakglass_ApprovesCallersSession(t *testing.T) {
	r, key := tokenRig(t)
	sessionFile(t, r.root, "9", "alice", "192.0.2.7", 4242)
	r.a.sessions(r.snap)
	if rep := r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000a1", "approve-session"), Session: "9"}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	r.now = r.now.Add(5 * time.Minute)
	r.a.sessions(r.snap)
	if len(r.kind("session-terminated")) != 0 {
		t.Fatal("approved session ended")
	}
	if got := r.kind("breakglass"); len(got) != 1 || !strings.Contains(got[0].Detail, "approve-session") || !strings.Contains(got[0].Detail, "session 9") {
		t.Fatalf("breakglass: %+v", got)
	}
}

func TestBreakglass_ApproveOnce(t *testing.T) {
	r, key := tokenRig(t)
	sessionFile(t, r.root, "9", "alice", "192.0.2.7", 4242)
	sessionFile(t, r.root, "10", "alice", "192.0.2.7", 4243)
	tok := mint(r, key, "00000000000000a2", "approve-session")
	r.a.onGate(sshgate.Msg{Token: tok, Session: "9"})
	if rep := r.a.onGate(sshgate.Msg{Token: tok, Session: "10"}); rep.OK || !strings.Contains(rep.Why, "used") {
		t.Fatalf("reuse: %+v", rep)
	}
	if r.a.approved["10"] {
		t.Fatal("10 approved")
	}
	// The use survives a restart.
	r.a.used = nil
	if rep := r.a.onGate(sshgate.Msg{Token: tok, Session: "10"}); rep.OK {
		t.Fatal("reused after restart")
	}
	if rep := r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000a3", "approve-session")}); rep.OK {
		t.Fatal("approve with no session")
	}
}

func TestBreakglass_PauseStopsKills(t *testing.T) {
	r, key := tokenRig(t)
	if rep := r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000b1", "pause")}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	p := mk(500, 1, 1000, "/tmp/x")
	r.snap = tree(p)
	r.a.handle(r.snap, []detect.Detection{egress(p)})
	if got := r.kind("egress"); len(got) != 1 || got[0].Action != "would-kill" || len(r.kills) != 0 {
		t.Fatalf("paused: %+v kills %d", got, len(r.kills))
	}
	r.now = r.now.Add(3 * time.Hour)
	r.a.handle(r.snap, []detect.Detection{egress(p)})
	if got := r.kind("egress"); len(got) != 2 || got[1].Action != "killed" {
		t.Fatalf("after expiry: %+v", got)
	}
}

func TestBreakglass_SpooledWhileDown(t *testing.T) {
	r, key := tokenRig(t)
	sessionFile(t, r.root, "9", "alice", "192.0.2.7", 4242)
	os.MkdirAll(r.a.spool, 0o700)
	os.WriteFile(filepath.Join(r.a.spool, "a.tok"), []byte(mint(r, key, "00000000000000c1", "approve-session")+"\n9\n"), 0o600)
	os.WriteFile(filepath.Join(r.a.spool, "b.tok"), []byte(mint(r, key, "00000000000000c2", "pause")+"\n"), 0o600)
	r.a.sessions(r.snap)
	if !r.a.approved["9"] || !r.a.paused() || len(r.kind("breakglass")) != 2 {
		t.Fatalf("approved %v paused %v: %+v", r.a.approved, r.a.paused(), r.kind("breakglass"))
	}
	r.a.sessions(r.snap)
	if len(r.kind("breakglass")) != 2 {
		t.Fatal("spool re-applied")
	}
}

// A non-root operator (the recovery account) must reach the spool: its
// parent, the state directory, can be passed through though not listed.
func TestMakeSpool_ReachableByOthers(t *testing.T) {
	state := filepath.Join(t.TempDir(), "xdr")
	os.MkdirAll(state, 0o700)
	if err := makeSpool(filepath.Join(state, "breakglass")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(state)
	if st.Mode().Perm() != 0o711 {
		t.Fatalf("state dir %v", st.Mode())
	}
	sp, _ := os.Stat(filepath.Join(state, "breakglass"))
	if sp.Mode()&os.ModeSticky == 0 || sp.Mode().Perm() != 0o733 {
		t.Fatalf("spool %v", sp.Mode())
	}
}

// An approval by break-glass holds across an agent restart, like an order.
func TestBreakglass_ApprovalSurvivesRestart(t *testing.T) {
	r, key := tokenRig(t)
	sessionFile(t, r.root, "9", "alice", "192.0.2.7", 4242)
	r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000d1", "approve-session"), Session: "9"})
	r.a.approved = nil
	r.a.loadOrders()
	if !r.a.approved["9"] {
		t.Fatal("break-glass approval lost on restart")
	}
}

func TestScanSpool_PrunesWhatCanNeverBeValid(t *testing.T) {
	r, key := tokenRig(t)
	os.MkdirAll(r.a.spool, 0o700)
	put := func(name, body string) { os.WriteFile(filepath.Join(r.a.spool, name), []byte(body), 0o600) }
	put("junk.tok", "not a token")
	put("forged.tok", mint(r, func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(nil); return k }(), "00000000000000e1", "pause")+"\n")
	expired := breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000e2", Host: "web01", Action: "pause", NotBefore: r.now.Add(-5 * time.Hour), Expires: r.now.Add(-4 * time.Hour)}, key)
	put("expired.tok", expired+"\n")
	put("other-host.tok", breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000e3", Host: "web02", Action: "pause", NotBefore: r.now.Add(-time.Minute), Expires: r.now.Add(time.Hour)}, key)+"\n")
	later := breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000e4", Host: "web01", Action: "pause", NotBefore: r.now.Add(time.Hour), Expires: r.now.Add(3 * time.Hour)}, key)
	put("later.tok", later+"\n")
	put("good.tok", mint(r, key, "00000000000000e5", "approve-session")+"\n9\n")
	r.a.scanSpool()
	left := map[string]bool{}
	ents, _ := os.ReadDir(r.a.spool)
	for _, e := range ents {
		left[e.Name()] = true
	}
	if left["junk.tok"] || left["forged.tok"] || left["expired.tok"] || left["other-host.tok"] {
		t.Fatalf("not pruned: %v", left)
	}
	if !left["later.tok"] || !left["good.tok"] {
		t.Fatalf("a token that can still be valid was removed: %v", left)
	}
}

// A session opened during a pause is not "late" when the pause ends: its
// grace starts then, so the operator who paused to get in has time.
func TestBreakglass_PauseEndRestartsGrace(t *testing.T) {
	r, key := tokenRig(t)
	r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000f1", "pause")})
	sessionFile(t, r.root, "9", "alice", "192.0.2.7", 4242)
	r.a.sessions(r.snap)
	r.now = r.now.Add(90 * time.Minute)
	r.a.sessions(r.snap)
	if len(r.kind("session-terminated")) != 0 {
		t.Fatal("ended during the pause")
	}
	r.now = r.now.Add(40 * time.Minute) // the pause (2h from the token's start) is over
	r.a.sessions(r.snap)
	if len(r.kind("session-terminated")) != 0 {
		t.Fatalf("ended at the moment the pause expired: %+v", r.kind("session-terminated"))
	}
	if len(r.kind("session-pending")) != 1 {
		t.Fatalf("no pending alert when the pause ended: %+v", r.kind("session-pending"))
	}
	r.now = r.now.Add(90 * time.Second)
	r.a.sessions(r.snap)
	if len(r.kind("session-terminated")) != 1 {
		t.Fatal("not ended after its grace")
	}
}

func TestBreakglass_UninstallRemovesTheInstall(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	r.a.layout = install.DefaultLayout()
	r.a.layout.Root = t.TempDir()
	r.a.runner = func(name string, args ...string) ([]byte, error) {
		order = append(order, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	r.a.exit = func() { order = append(order, "EXIT") }
	tok := mint(r, key, "00000000000000d1", "uninstall")
	rep := r.a.onGate(sshgate.Msg{Token: tok})
	if !rep.OK {
		t.Fatalf("%+v", rep)
	}
	if len(order) < 2 || !strings.HasPrefix(order[0], "systemctl disable --now") || order[len(order)-1] != "EXIT" {
		t.Fatalf("uninstall must run before the exit: %v", order)
	}
	got := r.kind("uninstall")
	if len(got) != 1 || got[0].Severity != model.SevCritical || got[0].Action != "uninstalled" ||
		!strings.Contains(got[0].Detail, "break-glass") || !strings.Contains(got[0].Detail, "00000000000000d1") {
		t.Fatalf("incident: %+v", got)
	}
	n := len(order)
	if rep := r.a.onGate(sshgate.Msg{Token: tok}); rep.OK || !strings.Contains(rep.Why, "used") {
		t.Fatalf("second use: %+v", rep)
	}
	if len(order) != n {
		t.Fatalf("a second use ran again: %v", order[n:])
	}
	// Another action's token never uninstalls, and nor does a bad one.
	r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000d2", "pause")})
	r.a.onGate(sshgate.Msg{Token: "junk.junk"})
	if len(order) != n {
		t.Fatalf("ran: %v", order[n:])
	}
}

func uninstallRigRun(t *testing.T, r *rig, order *[]string) {
	r.a.layout = install.DefaultLayout()
	r.a.layout.Root = t.TempDir()
	r.a.runner = func(name string, args ...string) ([]byte, error) {
		*order = append(*order, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	r.a.exit = func() { *order = append(*order, "EXIT") }
}

func TestBreakglass_UninstallSettlesAfterTheIncident(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	r.a.settle = func() {
		if len(r.kind("uninstall")) != 1 {
			t.Error("settle ran before the incident was recorded")
		}
		order = append(order, "SETTLE")
	}
	r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000d3", "uninstall")})
	if len(order) < 3 || order[0] != "SETTLE" || order[len(order)-1] != "EXIT" {
		t.Fatalf("%v", order)
	}
}

func TestBreakglass_UninstallFailureCanBeRetried(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	if err := os.MkdirAll(filepath.Dir(filepath.Join(r.a.layout.Root, r.a.layout.Manifest)), 0o755); err != nil {
		t.Fatal(err)
	}
	mf := filepath.Join(r.a.layout.Root, r.a.layout.Manifest)
	os.WriteFile(mf, []byte("not json"), 0o600)
	tok := mint(r, key, "00000000000000d4", "uninstall")
	if rep := r.a.onGate(sshgate.Msg{Token: tok}); rep.OK {
		t.Fatalf("a failed uninstall succeeded: %+v", rep)
	}
	for _, c := range order {
		if c == "EXIT" {
			t.Fatal("exited after a failure")
		}
	}
	failed := false
	for _, in := range r.kind("uninstall") {
		failed = failed || (in.Action == "alert" && strings.Contains(in.Detail, "failed"))
	}
	if !failed {
		t.Fatalf("no alert: %+v", r.kind("uninstall"))
	}
	os.Remove(mf)
	if rep := r.a.onGate(sshgate.Msg{Token: tok}); !rep.OK {
		t.Fatalf("retry refused: %+v", rep)
	}
	if order[len(order)-1] != "EXIT" {
		t.Fatalf("%v", order)
	}
}

func TestBreakglass_ExpiredUninstallInSpoolIsDropped(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	tok := breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000d5", Host: "web01", Action: "uninstall", NotBefore: r.now.Add(-4 * time.Hour), Expires: r.now.Add(-3 * time.Hour)}, key)
	os.MkdirAll(r.a.spool, 0o700)
	f := filepath.Join(r.a.spool, "old.tok")
	os.WriteFile(f, []byte(tok+"\n"), 0o600)
	r.a.scanSpool()
	if len(order) != 0 {
		t.Fatalf("ran: %v", order)
	}
	if _, err := os.Stat(f); err == nil {
		t.Fatal("expired token left in the spool")
	}
}

// The off switch takes the SSH gate out of PAM (its binary is about to go,
// and a gate that cannot run refuses every session), and after it the
// agent asserts nothing: no table, no gate, until it is gone.
func TestBreakglass_UninstallReleasesTheGate(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	testfs.File(t, r.root, "etc/ssh/sshd_config", "UsePAM yes\n", 0o644)
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.assert(false)
	pam := filepath.Join(r.root, "etc/pam.d/sshd")
	if b, _ := os.ReadFile(pam); !strings.Contains(string(b), "pam_exec.so") {
		t.Fatalf("the rig has no gate: %s", b)
	}
	if rep := r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000d9", "uninstall")}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	if b, _ := os.ReadFile(pam); string(b) != pamBase {
		t.Fatalf("the gate is still in pam.d/sshd:\n%s", b)
	}
	n := len(r.fw.applied)
	r.fw.drift = true
	r.a.guard()
	if b, _ := os.ReadFile(pam); string(b) != pamBase || len(r.fw.applied) != n {
		t.Fatalf("asserted after the uninstall: pam %q, %d applies", b, len(r.fw.applied)-n)
	}
}

// A pinned box gets its resolver files back before the install goes: it
// keeps name resolution once the agent (and its stub) are gone.
func TestBreakglass_UninstallRestoresDNS(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	resolv := filepath.Join(r.a.root, "etc/resolv.conf")
	os.MkdirAll(filepath.Dir(resolv), 0o755)
	os.WriteFile(resolv, []byte("nameserver 192.0.2.53\n"), 0o644)
	backup := filepath.Join(r.a.state, "dns-orig")
	os.MkdirAll(r.a.state, 0o755)
	if err := dnsguard.Save(r.a.root, backup); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(resolv, []byte("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"), 0o644)
	restoredFirst := false
	run := r.a.runner
	r.a.runner = func(name string, args ...string) ([]byte, error) {
		if len(order) == 0 {
			b, _ := os.ReadFile(resolv)
			restoredFirst = string(b) == "nameserver 192.0.2.53\n"
		}
		return run(name, args...)
	}
	if rep := r.a.onGate(sshgate.Msg{Token: mint(r, key, "00000000000000d5", "uninstall")}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	if !restoredFirst {
		t.Fatal("the resolver files were not restored before the uninstall ran")
	}
	if _, err := os.Stat(backup); err == nil {
		t.Fatal("the backup is still there")
	}
}

// The install's last step stops the agent's own unit, which ends this
// process: the token is spent, and its spool files removed, before that
// step, so neither a restart nor a reinstall finds it unused. A replay
// through the spool afterwards is refused, and the file pruned.
func TestBreakglass_UninstallSpentBeforeTheStop(t *testing.T) {
	r, key := tokenRig(t)
	var order []string
	uninstallRigRun(t, r, &order)
	tok := mint(r, key, "00000000000000e1", "uninstall")
	os.MkdirAll(r.a.spool, 0o700)
	spooled := filepath.Join(r.a.spool, "cli.tok") // as `xdr breakglass` leaves it
	os.WriteFile(spooled, []byte(tok+"\n\n"), 0o600)
	other := filepath.Join(r.a.spool, "pause.tok")
	os.WriteFile(other, []byte(mint(r, key, "00000000000000e2", "pause")+"\n"), 0o600)
	run := r.a.runner
	spent, unspooled := false, false
	r.a.runner = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && strings.Join(args, " ") == "stop xdr-agent.service" {
			b, _ := os.ReadFile(r.a.usedPath())
			spent = strings.Contains(string(b), "00000000000000e1")
			_, err := os.Stat(spooled)
			unspooled = os.IsNotExist(err)
		}
		return run(name, args...)
	}
	if rep := r.a.onGate(sshgate.Msg{Token: tok}); !rep.OK {
		t.Fatalf("%+v", rep)
	}
	if !spent || !unspooled {
		t.Fatalf("at the stop: spent %v, removed from the spool %v", spent, unspooled)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("another token's spool file was removed")
	}
	// A new agent on the box (a reinstall keeps the state directory), the
	// token spooled again: refused, nothing runs, the file goes.
	n := len(order)
	r.a.used, r.a.uninstalled, r.a.uninstTried = nil, false, false
	os.WriteFile(spooled, []byte(tok+"\n\n"), 0o600)
	r.a.scanSpool()
	if len(order) != n {
		t.Fatalf("a spent token replayed through the spool ran: %v", order[n:])
	}
	if _, err := os.Stat(spooled); !os.IsNotExist(err) {
		t.Fatal("a spent uninstall token was left in the spool")
	}
}

// With no install to remove nothing is said or spent: no "uninstalled"
// incident, no settle, the token still good.
func TestBreakglass_UninstallWithoutInstallSpendsNothing(t *testing.T) {
	r, key := tokenRig(t)
	settled := false
	r.a.settle = func() { settled = true }
	r.a.runner = nil
	tok := mint(r, key, "00000000000000e3", "uninstall")
	rep := r.a.onGate(sshgate.Msg{Token: tok})
	if rep.OK || !strings.Contains(rep.Why, "no install") {
		t.Fatalf("%+v", rep)
	}
	if got := r.kind("uninstall"); len(got) != 0 || settled {
		t.Fatalf("said %+v, settled %v", got, settled)
	}
	r.a.used = nil
	r.a.loadUsed()
	if _, ok := r.a.used["00000000000000e3"]; ok {
		t.Fatal("the token was spent")
	}
}
