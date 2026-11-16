package sshgate

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

type fakeCmds struct {
	ran     [][]string
	outputs int
	failT   bool // sshd -t fails
}

func (f *fakeCmds) run(name string, args ...string) error {
	f.ran = append(f.ran, append([]string{name}, args...))
	return nil
}

func (f *fakeCmds) output(name string, args ...string) ([]byte, error) {
	f.ran = append(f.ran, append([]string{name}, args...))
	if name == "sshd" && slices.Contains(args, "-t") {
		if f.failT {
			return []byte("line 3: Bad configuration option"), errors.New("exit status 255")
		}
		return nil, nil
	}
	f.outputs++
	return []byte("port 22\npasswordauthentication yes\nkbdinteractiveauthentication no\npubkeyauthentication yes\nauthenticationmethods any\n"), nil
}

func (f *fakeCmds) reloads() int {
	n := 0
	for _, r := range f.ran {
		if r[0] == "systemctl" {
			n++
		}
	}
	return n
}

func gateBase() *baseline.Baseline {
	return &baseline.Baseline{Files: map[string]baseline.FileEntry{
		"/etc/ssh/sshd_config": {Content: []byte(baseSSHD)},
		"/etc/pam.d/sshd":      {Content: []byte(basePAM)},
		"/etc/ssh/sshd_config.d/60-cloudimg-settings.conf": {Content: []byte("PasswordAuthentication no\n")},
	}}
}

func rig(t *testing.T) (*Asserter, *fakeCmds, string) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/ssh/sshd_config", baseSSHD, 0o644)
	testfs.File(t, root, "etc/pam.d/sshd", basePAM, 0o644)
	testfs.File(t, root, "etc/ssh/sshd_config.d/60-cloudimg-settings.conf", "PasswordAuthentication no\n", 0o644)
	f := &fakeCmds{}
	return &Asserter{Root: root, State: filepath.Join(t.TempDir(), "state"), Run: f.run, Output: f.output}, f, root
}

func read(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAssert_WritesAndReloads(t *testing.T) {
	a, f, root := rig(t)
	cfg := gateConfig(t, gateBody)
	changed, err := a.Assert(cfg, gateBase(), "/usr/local/sbin/xdr")
	if err != nil || len(changed) != 2 {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	if !strings.Contains(read(t, filepath.Join(root, "etc/ssh/sshd_config")), "AllowUsers root@192.0.2.7") ||
		!strings.Contains(read(t, filepath.Join(root, "etc/pam.d/sshd")), "pam_exec.so quiet /usr/local/sbin/xdr gate") {
		t.Fatal("not written")
	}
	if f.reloads() != 1 {
		t.Fatalf("reloads %d: %v", f.reloads(), f.ran)
	}
	if st, _ := os.Stat(filepath.Join(root, "etc/ssh/sshd_config")); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	changed, err = a.Assert(cfg, gateBase(), "/usr/local/sbin/xdr")
	if err != nil || len(changed) != 0 || f.reloads() != 1 {
		t.Fatalf("second: %v %v, reloads %d", changed, err, f.reloads())
	}
	testfs.File(t, root, "etc/pam.d/sshd", basePAM, 0o644) // someone took the gate out
	changed, _ = a.Assert(cfg, gateBase(), "/usr/local/sbin/xdr")
	if !slices.Equal(changed, []string{"/etc/pam.d/sshd"}) || f.reloads() != 2 {
		t.Fatalf("drift: %v, reloads %d", changed, f.reloads())
	}
}

func TestAssert_SSHDRejectedRestores(t *testing.T) {
	a, f, root := rig(t)
	testfs.File(t, root, "etc/ssh/sshd_config.d/00-evil.conf", "PermitRootLogin yes\n", 0o644)
	f.failT = true
	_, err := a.Assert(gateConfig(t, gateBody), gateBase(), "/usr/local/sbin/xdr")
	if err == nil || !strings.Contains(err.Error(), "sshd -t") {
		t.Fatalf("err %v", err)
	}
	if read(t, filepath.Join(root, "etc/ssh/sshd_config")) != baseSSHD || read(t, filepath.Join(root, "etc/pam.d/sshd")) != basePAM {
		t.Fatal("not restored")
	}
	if read(t, filepath.Join(root, "etc/ssh/sshd_config.d/00-evil.conf")) != "PermitRootLogin yes\n" {
		t.Fatal("quarantined drop-in not put back")
	}
	if f.reloads() != 0 {
		t.Fatal("reloaded a rejected config")
	}
}

func TestAssert_QuarantinesDropIn(t *testing.T) {
	a, _, root := rig(t)
	testfs.File(t, root, "etc/ssh/sshd_config.d/00-evil.conf", "PermitRootLogin yes\n", 0o644)
	testfs.File(t, root, "etc/ssh/sshd_config.d/60-cloudimg-settings.conf", "PasswordAuthentication yes\n", 0o644)
	changed, err := a.Assert(gateConfig(t, gateBody), gateBase(), "/usr/local/sbin/xdr")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc/ssh/sshd_config.d/00-evil.conf")); err == nil {
		t.Fatal("drop-in left in place")
	}
	q, _ := filepath.Glob(filepath.Join(a.State, "quarantine", "*-00-evil.conf"))
	if len(q) != 1 || read(t, q[0]) != "PermitRootLogin yes\n" {
		t.Fatalf("quarantine: %v", q)
	}
	if read(t, filepath.Join(root, "etc/ssh/sshd_config.d/60-cloudimg-settings.conf")) != "PasswordAuthentication no\n" {
		t.Fatal("baseline drop-in not put back to its baseline content")
	}
	if !slices.Contains(changed, "/etc/ssh/sshd_config.d/00-evil.conf") || !slices.Contains(changed, "/etc/ssh/sshd_config.d/60-cloudimg-settings.conf") {
		t.Fatalf("changed %v", changed)
	}
}

func TestAssert_NoBaseline(t *testing.T) {
	a, f, root := rig(t)
	b := gateBase()
	delete(b.Files, "/etc/pam.d/sshd")
	_, err := a.Assert(gateConfig(t, gateBody), b, "/x")
	if !errors.Is(err, ErrNoBase) || !strings.Contains(err.Error(), "/etc/pam.d/sshd") {
		t.Fatalf("err %v", err)
	}
	if read(t, filepath.Join(root, "etc/ssh/sshd_config")) != baseSSHD || len(f.ran) != 0 {
		t.Fatal("wrote or ran with the gate off")
	}
}

func TestT0_CapturedOnce(t *testing.T) {
	a, f, _ := rig(t)
	cfg := gateConfig(t, gateBody)
	for range 2 {
		t0, err := a.T0(cfg)
		if err != nil || t0 != (T0{Password: "yes", KbdInteractive: "no", Pubkey: "yes", Methods: "any"}) {
			t.Fatalf("%+v %v", t0, err)
		}
	}
	if f.outputs != 1 {
		t.Fatalf("sshd -T ran %d times", f.outputs)
	}
	want := []string{"sshd", "-T", "-C", "user=gray1,host=x,addr=192.0.2.7"}
	if !slices.Equal(f.ran[0], want) {
		t.Fatalf("ran %v", f.ran[0])
	}
	a2, f2, _ := rig(t)
	if t0, err := a2.T0(gateConfig(t, `{"jump":["192.0.2.7"],"ssh":{}}`)); err != nil || t0 != (T0{}) || f2.outputs != 0 {
		t.Fatalf("no gray: %+v %v", t0, err)
	}
}
