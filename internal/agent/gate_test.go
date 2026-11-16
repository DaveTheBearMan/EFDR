package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/model"
	"xdr/internal/sshgate"
	"xdr/internal/testfs"
)

// gateRig is a rig with the gate configured and fake sshd/systemctl.
func gateRig(t *testing.T, base *baseline.Baseline) (*rig, *[][]string) {
	r := newRig(t)
	r.a.cfg.SSH = &config.SSH{Blue: []string{"alice"}, Recovery: "xdrrecover", RecoveryKey: "ssh-ed25519 AAAA k", Grace: config.Duration{Duration: 90 * time.Second}}
	r.a.pol.Base = base
	var ran [][]string
	run := func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	r.a.ssh = &sshgate.Asserter{Root: r.root, State: filepath.Join(r.root, "var/lib/xdr"), Run: run,
		Output: func(name string, args ...string) ([]byte, error) {
			ran = append(ran, append([]string{name}, args...))
			return []byte("passwordauthentication no\n"), nil
		}}
	r.a.gateExe = "/usr/local/sbin/xdr"
	r.a.run = run
	return r, &ran
}

const pamBase = "@include common-auth\n@include common-session\n"

func TestAgent_GateOffWithoutBaselinePAM(t *testing.T) {
	r, ran := gateRig(t, &baseline.Baseline{Files: map[string]baseline.FileEntry{"/etc/ssh/sshd_config": {Content: []byte("UsePAM yes\n")}}})
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.guard()
	r.a.guard()
	got := r.kind("ssh-config")
	if len(got) != 1 || got[0].Severity != model.SevCritical {
		t.Fatalf("ssh-config: %+v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, "etc/pam.d/sshd")); string(b) != pamBase || len(*ran) != 0 {
		t.Fatalf("pam %q, ran %v", b, *ran)
	}
}

func TestAgent_SSHDriftRepaired(t *testing.T) {
	r, _ := gateRig(t, &baseline.Baseline{Files: map[string]baseline.FileEntry{
		"/etc/ssh/sshd_config": {Content: []byte("UsePAM yes\n")}, "/etc/pam.d/sshd": {Content: []byte(pamBase)}}})
	testfs.File(t, r.root, "etc/ssh/sshd_config", "UsePAM yes\n", 0o644)
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.assert(false) // the first write is not drift
	if len(r.kind("ssh-drift")) != 0 {
		t.Fatal("first write reported")
	}
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.guard()
	got := r.kind("ssh-drift")
	if len(got) != 1 || got[0].Severity != model.SevHigh || got[0].Detail != "/etc/pam.d/sshd restored" {
		t.Fatalf("ssh-drift: %+v", got)
	}
}

func sessionFile(t *testing.T, root, id, user, from string, leader int) {
	testfs.File(t, root, "run/systemd/sessions/"+id, "USER="+user+"\nUID=1001\nSERVICE=sshd\nCLASS=user\nREMOTE_HOST="+from+"\nLEADER="+strconv.Itoa(leader)+"\n", 0o644)
}

func gateOn(t *testing.T) (*rig, *[][]string) {
	r, ran := gateRig(t, &baseline.Baseline{
		Files:    map[string]baseline.FileEntry{"/etc/ssh/sshd_config": {Content: []byte("UsePAM yes\n")}, "/etc/pam.d/sshd": {Content: []byte(pamBase)}},
		Accounts: []baseline.Account{{Name: "root"}, {Name: "alice", UID: 1001}, {Name: "gray1", UID: 2001}},
	})
	r.snap = tree()
	return r, ran
}

func terminates(ran [][]string) int {
	n := 0
	for _, c := range ran {
		if c[0] == "loginctl" {
			n++
		}
	}
	return n
}

func TestAgentSessions_TerminateAfterGrace(t *testing.T) {
	r, ran := gateOn(t)
	sessionFile(t, r.root, "7", "alice", "192.0.2.7", 4242)
	start := r.now
	r.a.sessions(r.snap)
	if got := r.kind("session-pending"); len(got) != 1 || got[0].User != "alice" || !strings.Contains(got[0].Detail, "7") {
		t.Fatalf("pending: %+v", got)
	}
	r.now = start.Add(89 * time.Second)
	r.a.sessions(r.snap)
	if terminates(*ran) != 0 || len(r.kind("session-pending")) != 1 {
		t.Fatalf("early: %v", *ran)
	}
	r.now = start.Add(90 * time.Second)
	r.a.sessions(r.snap)
	r.a.sessions(r.snap)
	if terminates(*ran) != 1 || len(r.kind("session-terminated")) != 1 || r.kind("session-terminated")[0].Severity != model.SevHigh {
		t.Fatalf("terminate: %v %+v", *ran, r.kind("session-terminated"))
	}
	testfs.Remove(t, r.root, "run/systemd/sessions/7")
	r.a.sessions(r.snap)
	if len(r.a.sess) != 0 {
		t.Fatal("ended session not forgotten")
	}
}

func TestAgentSessions_GrayUIDChanged(t *testing.T) {
	r, _ := gateOn(t)
	testfs.File(t, r.root, "etc/passwd", "root:x:0:0::/root:/bin/bash\ngray1:x:0:0::/home/gray1:/bin/bash\n", 0o644)
	r.a.sessions(r.snap)
	r.a.sessions(r.snap)
	if got := r.kind("account-uid"); len(got) != 1 || got[0].Severity != model.SevCritical || got[0].User != "gray1" {
		t.Fatalf("account-uid: %+v", got)
	}
}

func TestAgentGate_RegistersAndRefuses(t *testing.T) {
	r, _ := gateOn(t)
	sessionFile(t, r.root, "7", "alice", "192.0.2.7", 4242)
	testfs.File(t, r.root, "run/systemd/sessions/9", "USER=evil\nUID=1500\nSERVICE=sshd\nREMOTE_HOST=192.0.2.7\nLEADER=4300\n", 0o644)
	testfs.File(t, r.root, "proc/4250/cgroup", "0::/user.slice/user-1001.slice/session-7.scope\n", 0o644)
	if rep := r.a.onGate(sshgate.Msg{Session: "7", User: "alice"}); !rep.OK {
		t.Fatalf("alice: %+v", rep)
	}
	if st := r.a.sess["7"]; st == nil || !st.first.Equal(r.now) {
		t.Fatalf("not registered: %+v", st)
	}
	r.now = r.now.Add(time.Minute)
	delete(r.a.sess, "7")
	if rep := r.a.onGate(sshgate.Msg{PPID: 4250, User: "alice"}); !rep.OK || r.a.sess["7"] == nil || !r.a.sess["7"].first.Equal(r.now) {
		t.Fatalf("by ppid: %+v %+v", rep, r.a.sess["7"])
	}
	if rep := r.a.onGate(sshgate.Msg{Session: "9", User: "evil"}); rep.OK || !strings.Contains(rep.Why, "user not in baseline") {
		t.Fatalf("evil: %+v", rep)
	}
	if got := r.kind("session-refused"); len(got) != 1 || got[0].User != "evil" {
		t.Fatalf("refused: %+v", got)
	}
	if rep := r.a.onGate(sshgate.Msg{Session: "404"}); rep.OK {
		t.Fatal("a session logind does not know let in")
	}
}
