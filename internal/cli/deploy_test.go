package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"xdr/deploy"
	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/console"
	"xdr/internal/controller"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

func setStdin(t *testing.T, s string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Seek(0, 0)
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() { os.Stdin = old; f.Close() })
}

func controllerRig(t *testing.T) (controller.ControllerLayout, *fakeSys) {
	t.Helper()
	l := controller.DefaultControllerLayout()
	l.Root = t.TempDir()
	f := &fakeSys{}
	oldL, oldR := controllerLayout, runner
	controllerLayout, runner = l, f.run
	t.Cleanup(func() { controllerLayout, runner = oldL, oldR })
	return l, f
}

func TestControllerInstallCLI(t *testing.T) {
	l, sys := controllerRig(t)
	dir := filepath.Join(t.TempDir(), "ctl")
	const pw = "a long enough passphrase"
	args := []string{"controller", "install", "--dir", dir, "--name", "192.0.2.7", "--protect", "198.51.100.4,198.51.100.5",
		"--recovery", "xdrrecover", "--auto", "root", "--gray", "gray1,gray2"}
	var so, se bytes.Buffer
	setStdin(t, "")
	if code := Run(args, &so, &se); code != 2 || !strings.Contains(se.String(), "empty") {
		t.Fatalf("an empty password: %d %q", code, se.String())
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the refused install made the directory")
	}
	so.Reset()
	se.Reset()
	setStdin(t, pw+"\n")
	if code := Run(args, &so, &se); code != 0 {
		t.Fatalf("install: %d %q", code, se.String())
	}
	if strings.Contains(so.String()+se.String(), pw) || strings.Contains(strings.Join(sys.cmds, "\n"), pw) {
		t.Fatal("the password was printed or passed on")
	}
	if !console.CheckPassword(dir, pw) {
		t.Fatal("the console password was not set")
	}
	c, err := controller.LoadConfig(filepath.Join(dir, "controller.json"))
	if err != nil || len(c.Protect) != 3 || len(c.GrayUsers) != 2 || c.Recovery != "xdrrecover" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := os.Stat(filepath.Join(l.Root, l.Unit)); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sys.cmds, "systemctl enable --now xdr-controller.service") {
		t.Fatalf("cmds %v", sys.cmds)
	}
	// Again, with nothing on stdin: the password is kept, nothing changes.
	so.Reset()
	setStdin(t, "")
	if code := Run(args, &so, &se); code != 0 || !strings.Contains(so.String(), "nothing changed") {
		t.Fatalf("second run: %d %q %q", code, so.String(), se.String())
	}
	if !console.CheckPassword(dir, pw) {
		t.Fatal("the second run changed the password")
	}
}

// addTargetRig is a controller directory with a controller.json, and the
// files add-target is given.
func addTargetRig(t *testing.T) (dir, listeners, recKey, base string) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "ctl")
	if err := pki.Init(dir, []string{"192.0.2.7"}); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "controller.json"), []byte(`{"listen": "192.0.2.7:2379", "protect": ["192.0.2.7"]}`), 0o600)
	tmp := t.TempDir()
	listeners = filepath.Join(tmp, "facts.json")
	os.WriteFile(listeners, []byte(`{"host": "web01", "listeners": [
		{"proto": "tcp", "port": 80, "exe": "/usr/sbin/apache2"},
		{"proto": "tcp", "port": 631, "exe": "/usr/sbin/cupsd"},
		{"proto": "packet", "exe": "/usr/lib/systemd/systemd-networkd"}],
		"accounts": [{"name": "alice", "uid": 1000, "shell": "/bin/bash"}]}`), 0o644)
	recKey = filepath.Join(tmp, "rec.pub")
	os.WriteFile(recKey, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleExample recovery\n"), 0o644)
	base = filepath.Join(tmp, "base.json.gz")
	f, _ := os.Create(base)
	baseline.Save(f, &baseline.Baseline{Schema: baseline.Schema, Host: "web01", Files: map[string]baseline.FileEntry{}})
	f.Close()
	return
}

type member struct {
	mode int64
	data []byte
	dir  bool
}

func untar(t *testing.T, path string) map[string]member {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	out := map[string]member{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = member{h.Mode, b, h.Typeflag == tar.TypeDir}
	}
}

func TestAddTargetCLI_Bundle(t *testing.T) {
	dir, listeners, recKey, base := addTargetRig(t)
	out := filepath.Join(t.TempDir(), "web01.tgz")
	var so, se bytes.Buffer
	args := []string{"controller", "add-target", "--dir", dir, "--host", "web01", "--out", out, "--listeners", listeners,
		"--scored", "tcp/80,udp/53", "--blue", "alice,bob", "--gray", "gray1", "--recovery", "xdrrecover",
		"--recovery-key", recKey, "--auto", "root", "--baseline", base}
	if code := Run(args, &so, &se); code != 0 {
		t.Fatalf("add-target: %d %q", code, se.String())
	}
	if !strings.Contains(so.String(), "install-target.sh") {
		t.Fatalf("no next step: %q", so.String())
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Fatalf("tarball mode %v", st.Mode())
	}
	m := untar(t, out)
	want := map[string]int64{"fleet/": 0o700, "fleet/ca.pem": 0o600, "fleet/host.pem": 0o600, "fleet/host-key.pem": 0o600,
		"fleet/rules.pub": 0o600, "agent.json": 0o600, "agent.json.sig": 0o644, "install-target.sh": 0o755, "baseline.json.gz": 0o600}
	for name, mode := range want {
		if got, ok := m[name]; !ok || got.mode != mode {
			t.Errorf("%s: %+v (want mode %o)", name, got.mode, mode)
		}
	}
	if len(m) != len(want) {
		t.Errorf("members %v", slices.Collect(func(yield func(string) bool) {
			for k := range m {
				if !yield(k) {
					return
				}
			}
		}))
	}
	if !bytes.Equal(m["install-target.sh"].data, deploy.InstallTarget) || len(deploy.InstallTarget) == 0 {
		t.Error("install-target.sh is not the embedded script")
	}
	// The bundle as the box sees it: the signature verifies with the rule
	// key in it and the real loader takes the config.
	box := t.TempDir()
	for _, name := range []string{"agent.json", "agent.json.sig", "fleet/rules.pub", "fleet/host.pem"} {
		os.MkdirAll(filepath.Dir(filepath.Join(box, name)), 0o700)
		os.WriteFile(filepath.Join(box, name), m[name].data, 0o600)
	}
	pub, err := rules.LoadPublic(filepath.Join(box, "fleet/rules.pub"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadSigned(filepath.Join(box, "agent.json"), pub)
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "web01" || c.Kill || len(c.Jump) != 1 || c.Jump[0].Addr().String() != "192.0.2.7" ||
		!slices.Equal(c.Fleet.Endpoints, []string{"192.0.2.7:2379"}) || !slices.Equal(c.XDRPorts, []uint16{7443, 2379}) {
		t.Fatalf("config %+v", c)
	}
	if !slices.Equal(c.Scored, []config.Port{{Proto: "tcp", Port: 80}, {Proto: "udp", Port: 53}}) {
		t.Fatalf("scored %+v", c.Scored)
	}
	if slices.ContainsFunc(c.Listeners, func(l config.Listener) bool { return l.Port == 80 }) ||
		!slices.Contains(c.Listeners, config.Listener{Proto: "tcp", Port: 631, Exe: "/usr/sbin/cupsd"}) ||
		!slices.Contains(c.Listeners, config.Listener{Proto: "packet", Exe: "/usr/lib/systemd/systemd-networkd"}) ||
		!slices.Contains(c.Listeners, config.Listener{Proto: "tcp", Port: 22, Exe: "/usr/sbin/sshd"}) {
		t.Fatalf("listeners %+v", c.Listeners)
	}
	if c.SSH == nil || !slices.Equal(c.SSH.Blue, []string{"alice", "bob"}) || c.SSH.Recovery != "xdrrecover" ||
		!strings.HasPrefix(c.SSH.RecoveryKey, "ssh-ed25519 ") || !slices.Equal(c.SSH.Auto, []string{"root"}) ||
		!slices.Equal(c.GrayUsers, []string{"gray1"}) {
		t.Fatalf("ssh %+v gray %v", c.SSH, c.GrayUsers)
	}
	if h, err := pki.HostName(filepath.Join(box, "fleet/host.pem")); err != nil || h != "web01" {
		t.Fatalf("host cert %q %v", h, err)
	}
	if hosts, _ := pki.Hosts(dir); !slices.Equal(hosts, []string{"web01"}) {
		t.Fatalf("hosts %v", hosts)
	}

	// The tarball is not overwritten unless --force.
	before, _ := os.ReadFile(out)
	se.Reset()
	if code := Run(args, &so, &se); code != 2 || !strings.Contains(se.String(), "--force") {
		t.Fatalf("overwrite: %d %q", code, se.String())
	}
	if after, _ := os.ReadFile(out); !bytes.Equal(before, after) {
		t.Fatal("the tarball changed")
	}
	if code := Run(append(args, "--force"), &so, &se); code != 0 {
		t.Fatalf("--force: %d %q", code, se.String())
	}
	if after, _ := os.ReadFile(out); bytes.Equal(before, after) {
		t.Fatal("--force did not write a new bundle")
	}
}

func TestAddTargetCLI_Minimal(t *testing.T) {
	dir, _, _, _ := addTargetRig(t)
	out := filepath.Join(t.TempDir(), "db01.tgz")
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "add-target", "--dir", dir, "--host", "db01", "--out", out, "--scored", "tcp/5432", "--kill", "on"}, &so, &se); code != 0 {
		t.Fatalf("%d %q", code, se.String())
	}
	m := untar(t, out)
	if _, ok := m["baseline.json.gz"]; ok {
		t.Fatal("a baseline with none given")
	}
	c, err := config.Parse(m["agent.json"].data)
	if err != nil || !c.Kill || c.SSH != nil || len(c.Listeners) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestAddTargetCLI_Refusals(t *testing.T) {
	dir, listeners, recKey, _ := addTargetRig(t)
	for i, extra := range [][]string{
		{"--host", "Web01", "--scored", "tcp/80"},
		{"--host", "root", "--scored", "tcp/80"},
		{"--host", "web 01", "--scored", "tcp/80"},
		{"--host", "", "--scored", "tcp/80"},
		{"--host", "web02", "--scored", ""},
		{"--host", "web02", "--scored", "tcp/0"},
		{"--host", "web02", "--scored", "icmp/5"},
		{"--host", "web02", "--scored", "tcp/x"},
		{"--host", "web02", "--scored", "80"},
		{"--host", "web02", "--scored", "tcp/70000"},
		{"--host", "web02", "--scored", "tcp/80,"},
		{"--host", "web02", "--scored", "tcp/80", "--kill", "maybe"},
		{"--host", "web02", "--scored", "tcp/80", "--recovery", "xdrrecover"},
		{"--host", "web02", "--scored", "tcp/80", "--recovery-key", recKey},
		{"--host", "web02", "--scored", "tcp/80", "--blue", "Alice!"},
		{"--host", "web02", "--scored", "tcp/80", "--gray", "alice", "--blue", "alice"},
		{"--host", "web02", "--scored", "tcp/80", "--listeners", recKey},
		{"--host", "web02", "--scored", "tcp/80", "--baseline", listeners},
	} {
		out := filepath.Join(t.TempDir(), "x.tgz")
		var so, se bytes.Buffer
		args := append([]string{"controller", "add-target", "--dir", dir, "--out", out}, extra...)
		if code := Run(args, &so, &se); code == 0 {
			t.Errorf("%d: accepted %v", i, extra)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%d: wrote %s", i, out)
		}
	}
	if hosts, _ := pki.Hosts(dir); len(hosts) != 0 {
		t.Fatalf("a refused add-target enrolled %v", hosts)
	}
}

func TestVersionBaselineCLI(t *testing.T) {
	var so, se bytes.Buffer
	if code := Run([]string{"version", "--baseline"}, &so, &se); code != 0 {
		t.Fatalf("%d %q", code, se.String())
	}
	b, err := baseline.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(so.String()); got != strconv.Itoa(len(b.Files)) {
		t.Fatalf("got %q, want %d", got, len(b.Files))
	}
}
