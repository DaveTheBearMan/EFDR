package cli

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/sshgate"
)

func TestGateCmd_FailClosed(t *testing.T) {
	old := gateSocket
	gateSocket = filepath.Join(t.TempDir(), "none.sock")
	t.Cleanup(func() { gateSocket = old })
	t.Setenv("PAM_TYPE", "open_session")
	t.Setenv("PAM_USER", "alice")
	var so, se bytes.Buffer
	if code := Run([]string{"gate"}, &so, &se); code == 0 || !strings.Contains(se.String(), "agent unreachable") {
		t.Fatalf("exit %d, %q", code, se.String())
	}
	t.Setenv("PAM_TYPE", "close_session")
	if code := Run([]string{"gate"}, &so, &se); code != 0 {
		t.Fatalf("close_session: exit %d", code)
	}
}

func serveGate(t *testing.T, handle func(sshgate.Msg) sshgate.Reply) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "gate.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); l.Close() })
	go sshgate.Serve(ctx, l, handle)
	return sock
}
