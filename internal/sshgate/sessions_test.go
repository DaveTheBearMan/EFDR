package sshgate

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeSessions(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "run/systemd/sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSessions_Parse(t *testing.T) {
	root := writeSessions(t, map[string]string{
		"7":     "# This is private data. Do not parse.\nUID=1001\nUSER=alice\nACTIVE=1\nSTATE=active\nREMOTE=1\nTYPE=tty\nCLASS=user\nSCOPE=session-7.scope\nSERVICE=sshd\nLEADER=4242\nREMOTE_HOST=192.0.2.7\n",
		"c1":    "UID=0\nUSER=root\nSERVICE=login\nCLASS=user\nSTATE=online\nLEADER=900\nSCOPE=session-c1.scope\n",
		"7.ref": "garbage",
	})
	got, err := Sessions(root)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b Session) int { return len(a.ID) - len(b.ID) })
	// "c1": logind's id for a session with no audit id; kept.
	if len(got) != 2 || got[1].ID != "c1" || got[1].Service != "login" {
		t.Fatalf("got %+v", got)
	}
	want := Session{ID: "7", User: "alice", Service: "sshd", Class: "user", State: "active", RemoteHost: "192.0.2.7",
		Scope: "session-7.scope", UID: 1001, Leader: 4242, RemoteAddr: netip.MustParseAddr("192.0.2.7")}
	if got[0] != want {
		t.Fatalf("got  %+v\nwant %+v", got[0], want)
	}
}

func TestSessions_NamedRemoteHost(t *testing.T) {
	root := writeSessions(t, map[string]string{"3": "USER=bob\nUID=1002\nSERVICE=sshd\nREMOTE_HOST=jump.example\nLEADER=7\n"})
	got, err := Sessions(root)
	if err != nil || len(got) != 1 || got[0].RemoteHost != "jump.example" || got[0].RemoteAddr.IsValid() {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := Sessions(t.TempDir()); err != nil || len(got) != 0 {
		t.Fatalf("no logind: %+v %v", got, err)
	}
}

func TestTerminate_RunsLoginctl(t *testing.T) {
	var got []string
	run := func(name string, args ...string) error { got = append([]string{name}, args...); return nil }
	if err := Terminate(run, "7"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"loginctl", "terminate-session", "7"}) {
		t.Fatalf("ran %v", got)
	}
	if err := Terminate(run, "7; rm"); err == nil {
		t.Fatal("bad id accepted")
	}
}
