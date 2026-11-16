package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/model"
	"xdr/internal/sshgate"
	"xdr/internal/testfs"
)

// gateRig is a rig with the gate configured and fake sshd/systemctl.
func gateRig(t *testing.T, base *baseline.Baseline) (*rig, *[][]string) {
	r := newRig(t)
	r.a.cfg.SSH = &config.SSH{Blue: []string{"alice"}, Recovery: "xdrrecover", RecoveryKey: "ssh-ed25519 AAAA k", Grace: config.Duration{Duration: 90 * time.Second}}
	r.a.pol.Base = base
	var ran [][]string
	run := func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	r.a.ssh = &sshgate.Asserter{Root: r.root, State: filepath.Join(r.root, "var/lib/xdr"), Run: run,
		Output: func(name string, args ...string) ([]byte, error) {
			ran = append(ran, append([]string{name}, args...))
			return []byte("passwordauthentication no\n"), nil
		}}
	r.a.gateExe = "/usr/local/sbin/xdr"
	r.a.run = run
	return r, &ran
}

const pamBase = "@include common-auth\n@include common-session\n"

func TestAgent_GateOffWithoutBaselinePAM(t *testing.T) {
	r, ran := gateRig(t, &baseline.Baseline{Files: map[string]baseline.FileEntry{"/etc/ssh/sshd_config": {Content: []byte("UsePAM yes\n")}}})
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.guard()
	r.a.guard()
	got := r.kind("ssh-config")
	if len(got) != 1 || got[0].Severity != model.SevCritical {
		t.Fatalf("ssh-config: %+v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(r.root, "etc/pam.d/sshd")); string(b) != pamBase || len(*ran) != 0 {
		t.Fatalf("pam %q, ran %v", b, *ran)
	}
}

func TestAgent_SSHDriftRepaired(t *testing.T) {
	r, _ := gateRig(t, &baseline.Baseline{Files: map[string]baseline.FileEntry{
		"/etc/ssh/sshd_config": {Content: []byte("UsePAM yes\n")}, "/etc/pam.d/sshd": {Content: []byte(pamBase)}}})
	testfs.File(t, r.root, "etc/ssh/sshd_config", "UsePAM yes\n", 0o644)
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.assert(false) // the first write is not drift
	if len(r.kind("ssh-drift")) != 0 {
		t.Fatal("first write reported")
	}
	testfs.File(t, r.root, "etc/pam.d/sshd", pamBase, 0o644)
	r.a.guard()
	got := r.kind("ssh-drift")
	if len(got) != 1 || got[0].Severity != model.SevHigh || got[0].Detail != "/etc/pam.d/sshd restored" {
		t.Fatalf("ssh-drift: %+v", got)
	}
}
