package controller

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type fakeSystemd struct{ calls [][]string }

func (f *fakeSystemd) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return nil, nil
}

func (f *fakeSystemd) ran(words ...string) bool {
	return slices.ContainsFunc(f.calls, func(c []string) bool { return slices.Equal(c, words) })
}

type installFixture struct {
	l      ControllerLayout
	sd     *fakeSystemd
	dir    string
	bin    string
	asked  int
	stored []string
}

func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	f := &installFixture{l: DefaultControllerLayout(), sd: &fakeSystemd{}}
	f.l.Root = t.TempDir()
	f.dir = filepath.Join(t.TempDir(), "ctl")
	f.bin = filepath.Join(t.TempDir(), "xdr")
	if err := os.WriteFile(f.bin, []byte("binary v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *installFixture) opts(pw string) InstallOptions {
	return InstallOptions{
		Dir: f.dir, Name: "192.0.2.7", Binary: f.bin,
		Password: func() (string, error) { f.asked++; return pw, nil },
		SetPassword: func(dir, p string) error {
			f.stored = append(f.stored, p)
			return os.WriteFile(filepath.Join(dir, "console.json"), []byte("{}"), 0o600)
		},
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallController_FirstRun(t *testing.T) {
	f := newInstallFixture(t)
	o := f.opts("a long enough passphrase")
	o.Protect = []string{"198.51.100.4"}
	o.Gray = []string{"gray1"}
	o.Auto = []string{"root"}
	o.Recovery = "xdrrecover"
	rep, err := InstallController(f.l, f.sd.run, o)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Initialised || !rep.PasswordSet {
		t.Fatalf("report %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "ca-key.pem")); err != nil {
		t.Fatal("no CA:", err)
	}
	c, err := LoadConfig(filepath.Join(f.dir, "controller.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "192.0.2.7:2379" || c.Console == nil || c.Console.Listen != "192.0.2.7:8443" {
		t.Fatalf("listen %q console %+v", c.Listen, c.Console)
	}
	var prot []string
	for _, n := range c.Protect {
		prot = append(prot, n.Addr().String())
	}
	if !slices.Contains(prot, "192.0.2.7") || !slices.Contains(prot, "198.51.100.4") {
		t.Fatalf("protect %v", prot)
	}
	if !slices.Equal(c.GrayUsers, []string{"gray1"}) || !slices.Equal(c.Auto, []string{"root"}) || c.Recovery != "xdrrecover" {
		t.Fatalf("config %+v", c)
	}
	if st, _ := os.Stat(filepath.Join(f.dir, "controller.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("controller.json mode %v", st.Mode())
	}
	if f.asked != 1 || !slices.Equal(f.stored, []string{"a long enough passphrase"}) {
		t.Fatalf("asked %d stored %v", f.asked, f.stored)
	}
	bin, err := os.ReadFile(filepath.Join(f.l.Root, "/usr/local/sbin/xdr"))
	if err != nil || string(bin) != "binary v1" {
		t.Fatalf("binary %q %v", bin, err)
	}
	if st, _ := os.Stat(filepath.Join(f.l.Root, "/usr/local/sbin/xdr")); st.Mode().Perm() != 0o755 {
		t.Fatalf("binary mode %v", st.Mode())
	}
	unit, err := os.ReadFile(filepath.Join(f.l.Root, "/etc/systemd/system/xdr-controller.service"))
	if err != nil {
		t.Fatal(err)
	}
	u := string(unit)
	for _, want := range []string{"\nExecStart=/usr/local/sbin/xdr controller run --dir " + f.dir + "\n", "\nRestart=always\n",
		"\nRestartSec=2\n", "\nLimitNOFILE=65536\n", "\nWantedBy=multi-user.target\n"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit lacks %q:\n%s", want, u)
		}
	}
	for _, bad := range []string{"network", "After=", "Requires=", "chattr"} {
		if strings.Contains(u, bad) {
			t.Errorf("unit has %q:\n%s", bad, u)
		}
	}
	if !f.sd.ran("systemctl", "daemon-reload") || !f.sd.ran("systemctl", "enable", "--now", "xdr-controller.service") {
		t.Fatalf("calls %v", f.sd.calls)
	}
	for _, c := range f.sd.calls {
		if c[0] != "systemctl" || strings.Contains(strings.Join(c, " "), "passphrase") {
			t.Fatalf("unexpected call %v", c)
		}
	}
}

func TestInstallController_SecondRunChangesNothing(t *testing.T) {
	f := newInstallFixture(t)
	if _, err := InstallController(f.l, f.sd.run, f.opts("a long enough passphrase")); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(f.dir, "controller.json"))
	f.sd.calls = nil
	rep, err := InstallController(f.l, f.sd.run, f.opts("a long enough passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Initialised || rep.PasswordSet || len(rep.Wrote) != 0 || f.asked != 1 {
		t.Fatalf("second run %+v, asked %d", rep, f.asked)
	}
	if again, _ := os.ReadFile(filepath.Join(f.dir, "controller.json")); string(again) != string(cfg) {
		t.Fatalf("controller.json changed:\n%s\n%s", cfg, again)
	}
	if f.sd.ran("systemctl", "restart", "xdr-controller.service") || !f.sd.ran("systemctl", "enable", "--now", "xdr-controller.service") {
		t.Fatalf("calls %v", f.sd.calls)
	}
	// A new binary is copied and the running controller restarted.
	os.WriteFile(f.bin, []byte("binary v2"), 0o755)
	f.sd.calls = nil
	rep, err = InstallController(f.l, f.sd.run, f.opts(""))
	if err != nil || !slices.Contains(rep.Wrote, "/usr/local/sbin/xdr") || !f.sd.ran("systemctl", "restart", "xdr-controller.service") {
		t.Fatalf("new binary: %+v %v %v", rep, err, f.sd.calls)
	}
}

func TestInstallController_MergeKeepsKeys(t *testing.T) {
	f := newInstallFixture(t)
	os.MkdirAll(f.dir, 0o700)
	old := `{"listen": "192.0.2.7:2400", "protect": ["203.0.113.0/24"], "guard_exes": ["/usr/sbin/apache2"],
	 "gray_users": ["gray9"], "console": {"listen": "192.0.2.7:9443"}, "future_key": {"a": 1}}`
	os.WriteFile(filepath.Join(f.dir, "controller.json"), []byte(old), 0o600)
	o := f.opts("a long enough passphrase")
	o.Gray = []string{"gray1", "gray9"}
	if _, err := InstallController(f.l, f.sd.run, o); err != nil {
		t.Fatal(err)
	}
	m := readJSON(t, filepath.Join(f.dir, "controller.json"))
	if m["listen"] != "192.0.2.7:2400" || m["console"].(map[string]any)["listen"] != "192.0.2.7:9443" {
		t.Fatalf("an existing value was replaced: %v", m)
	}
	if m["future_key"] == nil || m["guard_exes"] == nil {
		t.Fatalf("a key was dropped: %v", m)
	}
	prot := m["protect"].([]any)
	if len(prot) != 2 || prot[0] != "203.0.113.0/24" || prot[1] != "192.0.2.7" {
		t.Fatalf("protect %v", prot)
	}
	if g := m["gray_users"].([]any); len(g) != 2 || g[0] != "gray9" || g[1] != "gray1" {
		t.Fatalf("gray_users %v", g)
	}
	// --console-listen replaces the console address.
	o.ConsoleListen = "192.0.2.7:7000"
	if _, err := InstallController(f.l, f.sd.run, o); err != nil {
		t.Fatal(err)
	}
	if m := readJSON(t, filepath.Join(f.dir, "controller.json")); m["console"].(map[string]any)["listen"] != "192.0.2.7:7000" {
		t.Fatalf("console %v", m["console"])
	}
}

func TestInstallController_Refusals(t *testing.T) {
	f := newInstallFixture(t)
	if _, err := InstallController(f.l, f.sd.run, f.opts("")); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty password: %v", err)
	}
	if _, err := os.Stat(f.dir); !errors.Is(err, os.ErrNotExist) || len(f.sd.calls) != 0 {
		t.Fatalf("a refused install did something: %v %v", err, f.sd.calls)
	}
	for _, mod := range []func(*InstallOptions){
		func(o *InstallOptions) { o.Name = "jump.example" },
		func(o *InstallOptions) { o.Name = "" },
		func(o *InstallOptions) { o.Dir = "relative/ctl" },
		func(o *InstallOptions) { o.Dir = f.dir + " x" },
		func(o *InstallOptions) { o.ConsoleListen = "nonsense" },
		func(o *InstallOptions) { o.Protect = []string{"not-an-address"} },
	} {
		o := f.opts("a long enough passphrase")
		mod(&o)
		if _, err := InstallController(f.l, f.sd.run, o); err == nil {
			t.Errorf("accepted %+v", o)
		}
	}
	// With console.json there the password is not asked for, unless reset.
	f2 := newInstallFixture(t)
	if _, err := InstallController(f2.l, f2.sd.run, f2.opts("a long enough passphrase")); err != nil {
		t.Fatal(err)
	}
	o := f2.opts("another long passphrase")
	o.ResetPassword = true
	if rep, err := InstallController(f2.l, f2.sd.run, o); err != nil || !rep.PasswordSet || f2.asked != 2 {
		t.Fatalf("reset: %+v %v asked %d", rep, err, f2.asked)
	}
	o = f2.opts("")
	o.ResetPassword = true
	if _, err := InstallController(f2.l, f2.sd.run, o); err == nil {
		t.Fatal("an empty reset password was accepted")
	}
}
