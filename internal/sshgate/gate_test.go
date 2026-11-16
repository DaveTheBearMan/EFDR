package sshgate

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func serve(t *testing.T, handle func(Msg) Reply) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gate.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); l.Close() })
	go Serve(ctx, l, handle)
	return sock
}

var openEnv = map[string]string{"PAM_TYPE": "open_session", "PAM_USER": "alice", "PAM_RHOST": "192.0.2.7", "XDG_SESSION_ID": "7"}

func TestGate_RegistersSession(t *testing.T) {
	var got Msg
	sock := serve(t, func(m Msg) Reply { got = m; return Reply{OK: true} })
	if err := Check(openEnv, sock, func() bool { return false }); err != nil {
		t.Fatal(err)
	}
	if got.Session != "7" || got.User != "alice" || got.RHost != "192.0.2.7" || got.PPID == 0 {
		t.Fatalf("got %+v", got)
	}
	sock = serve(t, func(Msg) Reply { return Reply{Why: "user not in baseline"} })
	if err := Check(openEnv, sock, func() bool { return true }); err == nil || !strings.Contains(err.Error(), "user not in baseline") {
		t.Fatalf("refusal: %v", err)
	}
}

func TestGate_FailClosed(t *testing.T) {
	err := Check(openEnv, filepath.Join(t.TempDir(), "none.sock"), func() bool { return false })
	if err == nil || err.Error() != "gate: agent unreachable" {
		t.Fatalf("err %v", err)
	}
}

func TestGate_PauseTokenWhenAgentDown(t *testing.T) {
	none := filepath.Join(t.TempDir(), "none.sock")
	if err := Check(openEnv, none, func() bool { return true }); err != nil {
		t.Fatalf("paused: %v", err)
	}
	if err := Check(openEnv, none, func() bool { return false }); err == nil {
		t.Fatal("not paused, agent down: let in")
	}
}

func TestGate_IgnoresCloseSession(t *testing.T) {
	env := map[string]string{"PAM_TYPE": "close_session", "PAM_USER": "alice"}
	if err := Check(env, filepath.Join(t.TempDir(), "none.sock"), func() bool { return false }); err != nil {
		t.Fatal(err)
	}
}

func TestServe_BoundsMessage(t *testing.T) {
	called := false
	sock := serve(t, func(Msg) Reply { called = true; return Reply{OK: true} })
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(`{"Session":"` + strings.Repeat("a", 9000) + "\"}\n"))
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	if called || !strings.Contains(string(buf[:n]), `"OK":false`) {
		t.Fatalf("oversized message: called %v, reply %q", called, buf[:n])
	}
}
