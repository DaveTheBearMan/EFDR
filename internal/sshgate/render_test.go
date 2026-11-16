package sshgate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/config"
)

const baseSSHD = "Include /etc/ssh/sshd_config.d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\nSubsystem sftp /usr/lib/openssh/sftp-server\nMatch User anoncvs\n\tX11Forwarding no\n"

const basePAM = "@include common-auth\naccount    required     pam_nologin.so\n@include common-account\nsession [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close\n@include common-session\nsession    optional     pam_motd.so  motd=/run/motd.dynamic\n@include common-password\n"

func gateConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const gateBody = `{"jump":["192.0.2.7"],"gray_users":["gray1"],"ssh":{"blue_users":["alice"],"recovery":"xdrrecover","recovery_key":"ssh-ed25519 AAAA k","auto":["xdrops"]}}`

func TestRenderSSHD_Order(t *testing.T) {
	out := string(RenderSSHD([]byte(baseSSHD), gateConfig(t, gateBody), T0{Password: "no", KbdInteractive: "no", Pubkey: "yes", Methods: "any"}))
	ib, im := strings.Index(out, "Include /etc/ssh"), strings.Index(out, "Match all")
	for _, l := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin prohibit-password", "PubkeyAuthentication yes", "UsePAM yes", "AllowUsers "} {
		if i := strings.Index(out, l); i < 0 || i > ib {
			t.Errorf("%q not in the header:\n%s", l, out)
		}
	}
	if im < ib || !strings.Contains(out[im:], "Match User gray1") || !strings.Contains(out[im:], "Match User xdrrecover\n\tAuthenticationMethods publickey") {
		t.Errorf("trailer:\n%s", out)
	}
	allow := out[strings.Index(out, "AllowUsers "):]
	allow = allow[:strings.Index(allow, "\n")]
	for _, w := range []string{" alice@192.0.2.7", " root@192.0.2.7", " xdrrecover@192.0.2.7", " xdrops@192.0.2.7", " gray1"} {
		if !strings.Contains(allow+" ", w+" ") {
			t.Errorf("AllowUsers lacks %q: %s", w, allow)
		}
	}
	if !strings.Contains(out, baseSSHD) {
		t.Error("base not kept unchanged")
	}
}

func TestRenderSSHD_KeepsWayIn(t *testing.T) {
	for _, body := range []string{
		gateBody,
		`{"jump":["192.0.2.7","198.51.100.0/24"],"ssh":{}}`,
		`{"jump":["192.0.2.7"],"ssh":{"recovery":"xdrrecover","recovery_key":"k"}}`,
		`{"jump":["198.51.100.0/24"],"gray_users":["gray1","gray2"],"ssh":{"blue_users":["alice","bob"]}}`,
	} {
		c := gateConfig(t, body)
		out := string(RenderSSHD([]byte(baseSSHD), c, T0{}))
		for _, j := range c.Jump {
			if !strings.Contains(out, " root@"+netString(j)) {
				t.Errorf("%s: no root@%s:\n%s", body, netString(j), out)
			}
			if c.SSH.Recovery != "" && !strings.Contains(out, " "+c.SSH.Recovery+"@"+netString(j)) {
				t.Errorf("%s: no recovery from %s", body, netString(j))
			}
		}
	}
}

func TestRenderSSHD_GrayKeepsT0(t *testing.T) {
	out := string(RenderSSHD([]byte(baseSSHD), gateConfig(t, gateBody), T0{Password: "yes", KbdInteractive: "no", Pubkey: "yes", Methods: "password"}))
	if strings.Count(out, "PasswordAuthentication yes") != 1 {
		t.Fatalf("want exactly one PasswordAuthentication yes:\n%s", out)
	}
	gray := out[strings.Index(out, "Match User gray1"):]
	gray = gray[:strings.Index(gray[1:], "Match")+1]
	for _, l := range []string{"\tPasswordAuthentication yes", "\tKbdInteractiveAuthentication no", "\tPubkeyAuthentication yes", "\tAuthenticationMethods password"} {
		if !strings.Contains(gray, l) {
			t.Errorf("gray block lacks %q:\n%s", l, gray)
		}
	}
	if strings.Index(out, "PasswordAuthentication yes") < strings.Index(out, "Match User gray1") {
		t.Error("password allowed outside the gray block")
	}
	out = string(RenderSSHD([]byte(baseSSHD), gateConfig(t, gateBody), T0{Password: "yes", Methods: "any"}))
	if strings.Contains(out, "AuthenticationMethods any") {
		t.Error(`"any" written out`)
	}
}

func TestRenderPAM_ExemptSkipsGate(t *testing.T) {
	out, err := RenderPAM([]byte(basePAM), gateConfig(t, gateBody), "/usr/local/sbin/xdr")
	if err != nil {
		t.Fatal(err)
	}
	want := "@include common-session\n" +
		"session [success=1 default=ignore] pam_succeed_if.so quiet user in gray1:xdrrecover\n" +
		"session required pam_exec.so quiet /usr/local/sbin/xdr gate\n" +
		"session    optional     pam_motd.so"
	if !strings.Contains(string(out), want) {
		t.Fatalf("got:\n%s", out)
	}
	if !strings.HasPrefix(string(out), "@include common-auth\n") || !strings.HasSuffix(string(out), "@include common-password\n") {
		t.Fatalf("base not kept:\n%s", out)
	}
	if _, err := RenderPAM([]byte("@include common-auth\n"), gateConfig(t, gateBody), "/x"); err == nil {
		t.Fatal("base without common-session accepted")
	}
	out, _ = RenderPAM([]byte(basePAM), gateConfig(t, `{"jump":["192.0.2.7"],"ssh":{"blue_users":["alice"]}}`), "/x")
	if strings.Contains(string(out), "pam_succeed_if") || !strings.Contains(string(out), "pam_exec.so quiet /x gate") {
		t.Fatalf("no exempt accounts:\n%s", out)
	}
}

// The off switch takes the gate out of pam.d/sshd: with the agent and its
// binary gone, the pam_exec line would refuse every session.
func TestReleasePAM_TakesTheGateOut(t *testing.T) {
	root := t.TempDir()
	out, err := RenderPAM([]byte(basePAM), gateConfig(t, gateBody), "/usr/local/sbin/xdr")
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(root, "etc/pam.d"), 0o755)
	p := filepath.Join(root, "etc/pam.d/sshd")
	os.WriteFile(p, out, 0o644)
	if changed, err := ReleasePAM(root); err != nil || !changed {
		t.Fatalf("changed %v, %v", changed, err)
	}
	if b, _ := os.ReadFile(p); string(b) != basePAM {
		t.Fatalf("got:\n%s\nwant:\n%s", b, basePAM)
	}
	if changed, err := ReleasePAM(root); err != nil || changed {
		t.Fatalf("a second release: %v, %v", changed, err)
	}
	os.Remove(p)
	if changed, err := ReleasePAM(root); err != nil || changed {
		t.Fatalf("no file: %v, %v", changed, err)
	}
}

// fakeOut records commands; fail names one that fails.
type fakeOut struct {
	ran  []string
	fail string
	outs map[string]string
}

func (f *fakeOut) run(name string, args ...string) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	f.ran = append(f.ran, c)
	if f.fail != "" && strings.HasPrefix(c, f.fail) {
		return []byte("bad config"), errors.New("exit status 255")
	}
	return []byte(f.outs[c]), nil
}

const unitFiles = "systemctl list-unit-files --no-legend ssh.service sshd.service"

// The uninstall puts sshd_config back to the baseline's file it was
// rendered from, checks it with sshd -t and reloads sshd's own unit.
func TestReleaseSSHD_PutsTheBaseBack(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "etc/ssh/sshd_config")
	os.MkdirAll(filepath.Dir(p), 0o755)
	rendered := RenderSSHD([]byte(baseSSHD), gateConfig(t, gateBody), T0{Password: "yes", Methods: "any"})
	os.WriteFile(p, rendered, 0o600)
	f := &fakeOut{outs: map[string]string{unitFiles: "sshd.service enabled disabled\n"}}
	changed, err := ReleaseSSHD(root, f.run)
	if err != nil || !changed {
		t.Fatalf("changed %v err %v", changed, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != baseSSHD {
		t.Fatalf("sshd_config:\n%s", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	want := []string{"sshd -t -f " + p, unitFiles, "systemctl reload sshd.service"}
	if strings.Join(f.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", f.ran, want)
	}
	// Again: nothing of xdr's is left, nothing runs.
	f.ran = nil
	if changed, err := ReleaseSSHD(root, f.run); changed || err != nil || len(f.ran) != 0 {
		t.Fatalf("second: %v %v %q", changed, err, f.ran)
	}
	// No file: nothing.
	if changed, err := ReleaseSSHD(t.TempDir(), f.run); changed || err != nil {
		t.Fatalf("no file: %v %v", changed, err)
	}
}

// When sshd -t refuses the base the render stays: the box keeps its way
// in, and nothing is reloaded.
func TestReleaseSSHD_RefusedBaseKeepsTheRender(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "etc/ssh/sshd_config")
	os.MkdirAll(filepath.Dir(p), 0o755)
	rendered := RenderSSHD([]byte(baseSSHD), gateConfig(t, gateBody), T0{})
	os.WriteFile(p, rendered, 0o644)
	f := &fakeOut{fail: "sshd -t"}
	if _, err := ReleaseSSHD(root, f.run); err == nil {
		t.Fatal("no error")
	}
	if b, _ := os.ReadFile(p); string(b) != string(rendered) {
		t.Fatalf("not put back:\n%s", b)
	}
	for _, c := range f.ran {
		if strings.HasPrefix(c, "systemctl") {
			t.Fatalf("ran %q", f.ran)
		}
	}
	// A reload that fails is reported; the file stays restored.
	f = &fakeOut{fail: "systemctl reload", outs: map[string]string{unitFiles: "ssh.service enabled enabled\nsshd.service alias -\n"}}
	if changed, err := ReleaseSSHD(root, f.run); !changed || err == nil || !strings.Contains(strings.Join(f.ran, "|"), "systemctl reload ssh.service") {
		t.Fatalf("reload failure: %v %v %q", changed, err, f.ran)
	}
	if b, _ := os.ReadFile(p); string(b) != baseSSHD {
		t.Fatalf("not restored:\n%s", b)
	}
}

func TestUnitName(t *testing.T) {
	for in, want := range map[string]string{
		"ssh.service  enabled enabled\nsshd.service alias   -\n": "ssh.service",
		"sshd.service enabled disabled\n":                        "sshd.service",
		"":                                                       "",
		"sshd.service alias -\n":                                 "",
	} {
		if got := UnitName([]byte(in)); got != want {
			t.Errorf("UnitName(%q) = %q, want %q", in, got, want)
		}
	}
}
