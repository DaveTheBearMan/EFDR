package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrders_GrayRefused(t *testing.T) {
	dir, _ := fleetConfig(t)
	os.WriteFile(filepath.Join(dir, "controller.json"), []byte(`{"listen":"127.0.0.1:1","gray_users":["gray1"]}`), 0o600)
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "approve-user", "--dir", dir, "--host", "web01", "gray1"}, &so, &se); code == 0 || !strings.Contains(se.String(), "refused: gray1 is a protected account") {
		t.Fatalf("exit %d %q", code, se.String())
	}
	se.Reset()
	if code := Run([]string{"controller", "approve-session", "--dir", dir, "--host", "nope", "7"}, &so, &se); code == 0 || !strings.Contains(se.String(), "not enrolled") {
		t.Fatalf("not enrolled: %d %q", code, se.String())
	}
	se.Reset()
	if code := Run([]string{"controller", "kill-session", "--dir", dir, "--host", "web01", "7;x"}, &so, &se); code == 0 || !strings.Contains(se.String(), "not a session id") {
		t.Fatalf("bad id: %d %q", code, se.String())
	}
}
