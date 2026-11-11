package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestController_InitEnrollCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ctl")
	out := filepath.Join(t.TempDir(), "web01")
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "init", "--dir", dir, "--name", "127.0.0.1"}, &so, &se); code != 0 {
		t.Fatalf("init: %d %s", code, se.String())
	}
	if code := Run([]string{"controller", "enroll", "--dir", dir, "--host", "web01", "--out", out}, &so, &se); code != 0 {
		t.Fatalf("enroll: %d %s", code, se.String())
	}
	if _, err := os.Stat(filepath.Join(out, "host.pem")); err != nil {
		t.Fatal(err)
	}
	se.Reset()
	if code := Run([]string{"controller", "init", "--dir", dir}, &so, &se); code != 2 || se.Len() == 0 {
		t.Fatalf("init without --name: %d %q", code, se.String())
	}
	if code := Run([]string{"controller", "nope"}, &so, &se); code != 2 {
		t.Fatalf("unknown subcommand: %d", code)
	}
}
