package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A tool is looked up in the fixed system directories only, never on the
// inherited $PATH, and runs with a fixed environment.
func TestExec_FixedPathAndEnv(t *testing.T) {
	evil, sys := t.TempDir(), t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	script(t, evil, "chattr", "touch "+marker)
	script(t, sys, "chattr", "env")
	t.Setenv("PATH", evil+":"+os.Getenv("PATH"))
	t.Setenv("LD_PRELOAD", "/nonexistent/evil.so")
	t.Setenv("XDR_INHERITED", "yes")
	run := runnerIn([]string{sys})
	out, err := run("chattr", "+i", "/x")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the chattr on $PATH was run")
	}
	env := string(out)
	for _, bad := range []string{"LD_PRELOAD", "XDR_INHERITED", evil} {
		if strings.Contains(env, bad) {
			t.Errorf("the child's environment has %q:\n%s", bad, env)
		}
	}
	if !strings.Contains(env, "PATH="+SafePath+"\n") {
		t.Errorf("the child's PATH is not the fixed one:\n%s", env)
	}
	if _, err := run("no-such-tool-xdr"); err == nil {
		t.Error("a tool missing from the fixed directories ran")
	}
}

func TestExec_DefaultDirs(t *testing.T) {
	if SafePath != "/usr/sbin:/usr/bin:/sbin:/bin" {
		t.Fatalf("SafePath %q", SafePath)
	}
	c := Command("sh", "-c", "true")
	if !filepath.IsAbs(c.Path) || c.Env == nil {
		t.Fatalf("path %q env %v", c.Path, c.Env)
	}
}
