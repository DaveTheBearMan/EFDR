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
	"xdr/internal/sshgate"
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
