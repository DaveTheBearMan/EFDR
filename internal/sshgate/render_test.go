package sshgate

import (
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
