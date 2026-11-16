package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/install"
	"xdr/internal/rules"
	"xdr/internal/sshgate"
)

type fakeSys struct {
	mu   sync.Mutex
	cmds []string
}

func (f *fakeSys) run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		return []byte("active\n"), nil
	}
	return nil, nil
}

func selfRig(t *testing.T) (install.Layout, *fakeSys) {
	t.Helper()
	l := install.DefaultLayout()
	l.Root = t.TempDir()
	for p, c := range map[string]string{l.Config: "{}\n", l.Config + ".sig": "c2ln\n"} {
		full := filepath.Join(l.Root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o600)
	}
	f := &fakeSys{}
	oldL, oldR := layout, runner
	layout, runner = l, f.run
	t.Cleanup(func() { layout, runner = oldL, oldR })
	return l, f
}

func TestEnsureCLI_ExitCodes(t *testing.T) {
	l, _ := selfRig(t)
	var so, se bytes.Buffer
	if code := Run([]string{"ensure"}, &so, &se); code != 2 || !strings.Contains(se.String(), "not installed") {
		t.Fatalf("not installed: %d %q", code, se.String())
	}
	so.Reset()
	se.Reset()
	if code := Run([]string{"install"}, &so, &se); code != 0 {
		t.Fatalf("install: %d %s", code, se.String())
	}
	// The test binary is not a script, but it is a file and a hash: ensure only compares.
	so.Reset()
	if code := Run([]string{"ensure"}, &so, &se); code != 0 || so.Len() != 0 {
		t.Fatalf("a good box: %d %q", code, so.String())
	}
	os.Remove(filepath.Join(l.Root, "/etc/systemd/system/xdr-guard-a.service"))
	so.Reset()
	if code := Run([]string{"ensure"}, &so, &se); code != 3 || !strings.Contains(so.String(), "restored /etc/systemd/system/xdr-guard-a.service") {
		t.Fatalf("something restored: %d %q", code, so.String())
	}
	for _, c := range layout.Copies {
		os.WriteFile(filepath.Join(l.Root, c), []byte("trojan"), 0o755)
	}
	se.Reset()
	if code := Run([]string{"ensure"}, &so, &se); code != 2 || !strings.Contains(se.String(), "no copy") {
		t.Fatalf("no good copy: %d %q", code, se.String())
	}
}

func TestGuardCLI_NeedsAUnit(t *testing.T) {
	var so, se bytes.Buffer
	for _, args := range [][]string{{"guard"}, {"guard", "--watch", "ssh.service"}, {"guard", "--watch", "xdr-guard-b.service; reboot"}} {
		se.Reset()
		if code := Run(args, &so, &se); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func uninstallRig(t *testing.T) (string, *fakeSys, func(host, action string, nb, exp time.Time) string) {
	t.Helper()
	l, f := selfRig(t)
	old := gateSocket
	gateSocket = filepath.Join(t.TempDir(), "none.sock") // the agent is dead
	t.Cleanup(func() { gateSocket = old })
	ctl, bundle := filepath.Join(t.TempDir(), "ctl"), filepath.Join(t.TempDir(), "fleet")
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "init", "--dir", ctl, "--name", "192.0.2.7"}, &so, &se); code != 0 {
		t.Fatal(se.String())
	}
	if code := Run([]string{"controller", "enroll", "--dir", ctl, "--host", "web01", "--out", bundle}, &so, &se); code != 0 {
		t.Fatal(se.String())
	}
	fd := filepath.Join(l.Root, l.FleetDir)
	os.MkdirAll(fd, 0o755)
	for _, n := range []string{"host.pem", "rules.pub"} {
		b, _ := os.ReadFile(filepath.Join(bundle, n))
		os.WriteFile(filepath.Join(fd, n), b, 0o600)
	}
	key, err := rules.LoadPrivate(filepath.Join(ctl, "rules.key"))
	if err != nil {
		t.Fatal(err)
	}
	return l.Root, f, func(host, action string, nb, exp time.Time) string {
		return breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000e1", Host: host, Action: action, NotBefore: nb, Expires: exp}, key)
	}
}

func TestUninstallCLI(t *testing.T) {
	_, f, mint := uninstallRig(t)
	now := time.Now()
	for name, c := range map[string]struct{ tok, msg string }{
		"expired":      {mint("web01", "uninstall", now.Add(-3*time.Hour), now.Add(-2*time.Hour)), "expired"},
		"not yet":      {mint("web01", "uninstall", now.Add(time.Hour), now.Add(2*time.Hour)), "not yet valid"},
		"another host": {mint("web02", "uninstall", now.Add(-time.Minute), now.Add(time.Hour)), "another host"},
		"approve":      {mint("web01", "approve-session", now.Add(-time.Minute), now.Add(time.Hour)), "not uninstall"},
		"junk":         {"abc.def", "bad signature"},
	} {
		var so, se bytes.Buffer
		if code := Run([]string{"uninstall", "--token", c.tok}, &so, &se); code == 0 || !strings.Contains(se.String(), c.msg) {
			t.Errorf("%s: exit %d %q", name, code, se.String())
		}
		if len(f.cmds) != 0 {
			t.Fatalf("%s: ran %v", name, f.cmds)
		}
	}
	var so, se bytes.Buffer
	good := mint("web01", "uninstall", now.Add(-time.Minute), now.Add(time.Hour))
	if code := Run([]string{"uninstall", "--token", good}, &so, &se); code != 0 {
		t.Fatalf("valid: %d %s", code, se.String())
	}
	if len(f.cmds) == 0 || !strings.HasPrefix(f.cmds[0], "systemctl disable --now") {
		t.Fatalf("cmds %v", f.cmds)
	}
}

// With the agent dead, the CLI's uninstall also takes the gate out of PAM.
func TestUninstallCLI_ReleasesTheGate(t *testing.T) {
	root, _, mint := uninstallRig(t)
	pam := filepath.Join(root, "etc/pam.d/sshd")
	os.MkdirAll(filepath.Dir(pam), 0o755)
	base := "@include common-auth\n@include common-session\n"
	os.WriteFile(pam, []byte(base+"session required pam_exec.so quiet /usr/local/sbin/xdr gate\n"), 0o644)
	now := time.Now()
	var so, se bytes.Buffer
	if code := Run([]string{"uninstall", "--token", mint("web01", "uninstall", now.Add(-time.Minute), now.Add(time.Hour))}, &so, &se); code != 0 {
		t.Fatalf("%d %s", code, se.String())
	}
	if b, _ := os.ReadFile(pam); string(b) != base {
		t.Fatalf("pam.d/sshd:\n%s", b)
	}
}

// With the agent alive the CLI refuses: the agent uninstalls itself, from
// the token sent with `xdr breakglass`.
func TestUninstallCLI_AgentAliveRefuses(t *testing.T) {
	_, f, mint := uninstallRig(t)
	gateSocket = serveGate(t, func(sshgate.Msg) sshgate.Reply { return sshgate.Reply{} })
	now := time.Now()
	var so, se bytes.Buffer
	code := Run([]string{"uninstall", "--token", mint("web01", "uninstall", now.Add(-time.Minute), now.Add(time.Hour))}, &so, &se)
	if code == 0 || !strings.Contains(se.String(), "xdr breakglass") {
		t.Fatalf("exit %d %q", code, se.String())
	}
	if len(f.cmds) != 0 {
		t.Fatalf("ran %v", f.cmds)
	}
}
