package sshgate

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestServe_PeerUIDFromKernel(t *testing.T) {
	var got Msg
	sock := serve(t, func(m Msg) Reply { got = m; return Reply{OK: true} })
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A client cannot claim to be root: the uid is the kernel's.
	c.Write([]byte(`{"Session":"7","PeerUID":0,"PeerPID":1}` + "\n"))
	buf := make([]byte, 128)
	c.Read(buf)
	if got.PeerUID != uint32(os.Getuid()) || got.PeerPID != os.Getpid() {
		t.Fatalf("peer %d/%d, want %d/%d", got.PeerUID, got.PeerPID, os.Getuid(), os.Getpid())
	}
}

// Idle connections of ordinary users must not use up the slots of root's
// (the gate's), or every blue login would be refused.
func TestServe_NonRootCannotStarveRoot(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	sock := serve(t, func(Msg) Reply { <-block; return Reply{OK: true} })
	var held []net.Conn
	for range nonRootConns {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(`{"Session":"1"}` + "\n"))
		held = append(held, c)
	}
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	time.Sleep(100 * time.Millisecond)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	c.Write([]byte(`{"Session":"2"}` + "\n"))
	buf := make([]byte, 128)
	if n, _ := c.Read(buf); n != 0 {
		t.Fatalf("a non-root connection past its share was served: %q", buf[:n])
	}
}

func TestServe_RootKeepsItsSlots(t *testing.T) {
	old := isRoot
	isRoot = func(uint32) bool { return true }
	t.Cleanup(func() { isRoot = old })
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	served := make(chan struct{}, 64)
	sock := serve(t, func(Msg) Reply { served <- struct{}{}; <-block; return Reply{OK: true} })
	for range nonRootConns + 5 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(`{"Session":"1"}` + "\n"))
	}
	for i := range nonRootConns + 5 {
		select {
		case <-served:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of %d root connections served", i, nonRootConns+5)
		}
	}
}
