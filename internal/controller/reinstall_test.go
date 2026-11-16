package controller

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"xdr/internal/pki"
	"xdr/internal/rules"
	"xdr/internal/sign"
)

type sshCall struct {
	addr, cmd string
	stdin     []byte
}

type fakeSSH struct {
	mu    sync.Mutex
	calls []sshCall
	err   error
	ran   chan struct{}
}

func (f *fakeSSH) Run(ctx context.Context, addr, command string, stdin io.Reader) error {
	var b []byte
	if stdin != nil {
		b, _ = io.ReadAll(stdin)
	}
	f.mu.Lock()
	f.calls = append(f.calls, sshCall{addr, command, b})
	f.mu.Unlock()
	if f.ran != nil {
		f.ran <- struct{}{}
	}
	return f.err
}

func (f *fakeSSH) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// reinstallRig is a controller directory with web01 enrolled, an agent
// config for it, a key file and a binary.
func reinstallRig(t *testing.T) (dir string, cfg *Config, bin, keyFile string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "ctl")
	if err := pki.Init(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := pki.Enroll(dir, "web01", filepath.Join(root, "web01")); err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(root, "web01.json")
	os.WriteFile(agent, []byte(`{"host":"web01"}`), 0o600)
	bin = filepath.Join(root, "xdr")
	os.WriteFile(bin, []byte("\x7fELF pretend binary"), 0o700)
	keyFile = filepath.Join(root, "id_ed25519")
	os.WriteFile(keyFile, []byte("PRIVATE-KEY-MATERIAL-XYZZY"), 0o600)
	cfg = &Config{Reinstall: &ReinstallConfig{Key: keyFile, User: "root",
		Hosts: map[string]ReinstallHost{"web01": {Addr: "192.0.2.5", Config: agent}}}}
	return
}

func untar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		d, _ := io.ReadAll(tr)
		out[h.Name] = d
	}
}

func TestReinstall_Steps(t *testing.T) {
	dir, cfg, bin, keyFile := reinstallRig(t)
	f := &fakeSSH{}
	if err := Reinstall(context.Background(), dir, cfg, "web01", f, bin); err != nil {
		t.Fatal(err)
	}
	if f.n() != 1 || f.calls[0].addr != "192.0.2.5" {
		t.Fatalf("calls: %+v", f.calls)
	}
	c := f.calls[0]
	i := func(s string) int { return strings.Index(c.cmd, s) }
	if i("mktemp -d") < 0 || !(i("mktemp -d") < i("tar -x") && i("tar -x") < i("install --config /etc/xdr/agent.json")) {
		t.Fatalf("order of the steps: %s", c.cmd)
	}
	files := untar(t, c.stdin)
	src, _ := os.ReadFile(bin)
	if sha256.Sum256(files["xdr"]) != sha256.Sum256(src) {
		t.Fatal("the pushed binary differs from the source")
	}
	for _, n := range []string{"ca.pem", "host.pem", "host-key.pem", "rules.pub"} {
		if len(files["fleet/"+n]) == 0 {
			t.Fatalf("bundle lacks %s: %v", n, files)
		}
	}
	conf := files["agent.json"]
	if string(conf) != `{"host":"web01"}` {
		t.Fatalf("config: %q", conf)
	}
	pub, err := rules.LoadPublic(filepath.Join(dir, "rules.pub"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(files["agent.json.sig"])))
	if err != nil || !sign.Verify("config", conf, sig, pub) {
		t.Fatalf("the signature does not verify: %v", err)
	}
	for _, p := range [][]byte{[]byte(c.cmd), c.stdin} {
		if bytes.Contains(p, []byte("PRIVATE-KEY-MATERIAL")) || strings.Contains(string(p), keyFile) {
			t.Fatal("the ssh key or its path went over the connection")
		}
	}
	if err := Reinstall(context.Background(), dir, cfg, "web01", &fakeSSH{err: errors.New("boom")}, bin); err == nil {
		t.Fatal("an ssh failure was swallowed")
	}
}

func TestReinstall_RemoteCommand(t *testing.T) {
	dir, cfg, bin, _ := reinstallRig(t)
	for _, user := range []string{"root", "ops"} {
		cfg.Reinstall.User = user
		f := &fakeSSH{}
		if err := Reinstall(context.Background(), dir, cfg, "web01", f, bin); err != nil {
			t.Fatal(err)
		}
		cmd := f.calls[0].cmd
		if out, err := exec.Command("sh", "-n", "-c", cmd).CombinedOutput(); err != nil {
			t.Fatalf("%s: command is not well-formed: %v %s\n%s", user, err, out, cmd)
		}
		if user != "root" {
			if !strings.HasPrefix(cmd, "sudo -n sh -c '") || !strings.HasSuffix(cmd, "'") {
				t.Fatalf("sudo wrapper: %s", cmd)
			}
			// the wrapper is the only quoting: the script inside has none
			if strings.Count(cmd, "'") != 2 {
				t.Fatalf("script has single quotes inside the sudo wrapper: %s", cmd)
			}
			if !strings.Contains(cmd, `\$d`) && strings.Contains(cmd, "trap ") && !strings.Contains(cmd, `trap "rm -rf \$d"`) {
				t.Fatalf("$d would expand early: %s", cmd)
			}
		}
		if len(untar(t, f.calls[0].stdin)) == 0 || strings.Index(cmd, "mktemp") > strings.Index(cmd, "tar -x") {
			t.Fatalf("%s: tar payload / order", user)
		}
	}
}

func TestReinstall_ClearsImmutable(t *testing.T) {
	dir, cfg, bin, _ := reinstallRig(t)
	f := &fakeSSH{}
	if err := Reinstall(context.Background(), dir, cfg, "web01", f, bin); err != nil {
		t.Fatal(err)
	}
	cmd := f.calls[0].cmd
	ch := strings.Index(cmd, "chattr -i -R /etc/xdr/fleet /etc/xdr/agent.json /etc/xdr/agent.json.sig")
	if ch < 0 {
		t.Fatalf("no chattr -i of the old files: %s", cmd)
	}
	for _, op := range []string{"rm -rf /etc/xdr/fleet", `mv "$d/fleet"`, "cp \"$d/agent.json\" /etc/xdr/agent.json", "cp \"$d/agent.json.sig\""} {
		i := strings.Index(cmd, op)
		if i < 0 || i < ch {
			t.Fatalf("%q at %d, not after chattr at %d", op, i, ch)
		}
	}
	if !strings.Contains(cmd[ch:], "|| true") {
		t.Fatal("chattr failure (not immutable, no chattr) must not abort")
	}
}

func TestReinstall_Refusals(t *testing.T) {
	dir, cfg, bin, keyFile := reinstallRig(t)
	other := filepath.Join(filepath.Dir(bin), "db01.json")
	os.WriteFile(other, []byte(`{}`), 0o600)

	// not enrolled, though listed
	c1 := *cfg
	c1.Reinstall = &ReinstallConfig{Key: keyFile, User: "root", Hosts: map[string]ReinstallHost{
		"web01": cfg.Reinstall.Hosts["web01"], "ghost": {Addr: "192.0.2.9", Config: other}}}
	// enrolled, not listed
	if err := pki.Enroll(dir, "db01", filepath.Join(filepath.Dir(bin), "db01")); err != nil {
		t.Fatal(err)
	}
	inject := &Config{Reinstall: &ReinstallConfig{Key: keyFile, User: "root", Hosts: map[string]ReinstallHost{
		"web01": {Addr: "192.0.2.4; reboot", Config: cfg.Reinstall.Hosts["web01"].Config}}}}
	relKey := &Config{Reinstall: &ReinstallConfig{Key: "id_ed25519", User: "root", Hosts: cfg.Reinstall.Hosts}}
	relCfg := &Config{Reinstall: &ReinstallConfig{Key: keyFile, User: "root", Hosts: map[string]ReinstallHost{
		"web01": {Addr: "192.0.2.5", Config: "web01.json"}}}}
	badUser := &Config{Reinstall: &ReinstallConfig{Key: keyFile, User: "root; id", Hosts: cfg.Reinstall.Hosts}}
	cases := []struct {
		name string
		cfg  *Config
		host string
	}{
		{"unenrolled", &c1, "ghost"},
		{"unlisted", cfg, "db01"},
		{"no reinstall section", &Config{}, "web01"},
		{"injected addr", inject, "web01"},
		{"relative key", relKey, "web01"},
		{"relative config", relCfg, "web01"},
		{"bad user", badUser, "web01"},
		{"bad host name", cfg, "web01;id"},
	}
	for _, c := range cases {
		f := &fakeSSH{}
		if err := Reinstall(context.Background(), dir, c.cfg, c.host, f, bin); err == nil || f.n() != 0 {
			t.Errorf("%s: err %v, %d commands", c.name, err, f.n())
		}
	}
}

func TestTrigger_AfterSilenceOncePerEpisode(t *testing.T) {
	dir, cfg, bin, _ := reinstallRig(t)
	cfg.Reinstall.After.Duration = time.Minute
	now := time.Unix(1_000_000, 0)
	ctl := &Controller{dir: dir, beats: map[string]*beat{}, now: func() time.Time { return now }}
	f := &fakeSSH{}
	ctl.EnableReinstall(cfg, f, bin)
	step := func(d time.Duration) {
		now = now.Add(d)
		ctl.checkReinstall()
		ctl.rwg.Wait()
	}
	ctl.heartbeat("web01", true)
	ctl.heartbeat("web01", false) // silent
	step(30 * time.Second)
	if f.n() != 0 {
		t.Fatal("ran before After")
	}
	step(30 * time.Second)
	if f.n() != 1 {
		t.Fatalf("at After: %d", f.n())
	}
	step(2 * time.Minute)
	if f.n() != 1 {
		t.Fatalf("a second in the same episode: %d", f.n())
	}
	ctl.heartbeat("web01", true) // back
	ctl.heartbeat("web01", false)
	step(time.Minute) // new episode, but under 5 minutes since the last
	if f.n() != 1 {
		t.Fatalf("rate limit broken: %d", f.n())
	}
	step(5 * time.Minute)
	if f.n() != 2 {
		t.Fatalf("new episode after 5 min: %d", f.n())
	}
	// a silent host not listed is left alone
	ctl.heartbeat("db01", false)
	step(time.Hour)
	if f.n() != 2 {
		t.Fatalf("unlisted host reinstalled: %d", f.n())
	}
}

func TestConfig_Reinstall(t *testing.T) {
	p := filepath.Join(t.TempDir(), "controller.json")
	load := func(s string) (*Config, error) {
		os.WriteFile(p, []byte(s), 0o600)
		return LoadConfig(p)
	}
	c, err := load(`{"listen":"127.0.0.1:2379","reinstall":{"key":"/root/k","hosts":{"web01":{"addr":"192.0.2.5","config":"/etc/xdr/web01.json"}}}}`)
	if err != nil || c.Reinstall == nil || c.Reinstall.After.Duration != 60*time.Second || c.Reinstall.User != "root" {
		t.Fatalf("defaults: %+v %v", c.Reinstall, err)
	}
	c, err = load(`{"listen":"127.0.0.1:2379","reinstall":{"key":"/k","user":"ops","after":"5m","hosts":{}}}`)
	if err != nil || c.Reinstall.After.Duration != 5*time.Minute || c.Reinstall.User != "ops" {
		t.Fatalf("explicit: %+v %v", c.Reinstall, err)
	}
	for _, bad := range []string{
		`"key":"k","hosts":{}`,
		`"key":"/k","hosts":{"web01":{"addr":"192.0.2.5","config":"rel.json"}}`,
		`"key":"/k","hosts":{"web01":{"addr":"192.0.2.4; reboot","config":"/c.json"}}`,
		`"key":"/k","hosts":{"Web 01":{"addr":"192.0.2.5","config":"/c.json"}}`,
		`"key":"/k","user":"a b","hosts":{}`,
		`"key":"","hosts":{}`,
	} {
		if _, err := load(`{"listen":"127.0.0.1:2379","reinstall":{` + bad + `}}`); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The script runs every tool from the system directories, with no
// inherited loader variables.
func TestReinstall_ScriptFixedPath(t *testing.T) {
	if !strings.HasPrefix(script, "set -e\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\nunset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT\n") {
		t.Fatalf("the script does not fix PATH first:\n%s", script)
	}
}

// The local ssh keeps only the tail of what it prints, never the whole of
// it, and is told to forward nothing and offer only the key.
func TestExecSSH_CappedOutputAndOptions(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "ssh")
	args := filepath.Join(dir, "args")
	// Over 10 MB of output, then fail so the tail is reported.
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + args + "\nhead -c 12000000 /dev/zero | tr '\\0' x\necho THE-END\nexit 3\n"
	if err := os.WriteFile(fake, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	e := ExecSSH{Key: "/k", User: "root", Bin: fake}
	err := e.Run(context.Background(), "192.0.2.5", "true", strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "THE-END") || len(err.Error()) > 1024 {
		t.Fatalf("err (%d bytes): %.200v", len(fmt.Sprint(err)), err)
	}
	b, _ := os.ReadFile(args)
	got := strings.Fields(string(b))
	for _, o := range []string{"ForwardAgent=no", "IdentitiesOnly=yes", "ClearAllForwardings=yes", "BatchMode=yes", "StrictHostKeyChecking=accept-new"} {
		if !slices.Contains(got, o) {
			t.Errorf("ssh args lack %s: %v", o, got)
		}
	}
	tw := &tailWriter{}
	for i := 0; i < 20000; i++ {
		tw.Write(make([]byte, 1000))
	}
	tw.Write([]byte("tail"))
	if cap(tw.buf) > 4096 || !strings.HasSuffix(string(tw.buf), "tail") || len(tw.buf) != tailKeep {
		t.Fatalf("kept %d (cap %d)", len(tw.buf), cap(tw.buf))
	}
}

// The payload lands under /var/lib/xdr, not a world-writable /tmp.
func TestReinstall_ScriptStagesUnderVarLib(t *testing.T) {
	if !strings.Contains(script, "mkdir -p /var/lib/xdr\nd=$(mktemp -d /var/lib/xdr/.reinstall.XXXXXX)\n") || strings.Contains(script, "mktemp -d)") {
		t.Fatalf("script:\n%s", script)
	}
}

// A disabled host is never reinstalled: it was cut off on purpose.
func TestTrigger_SkipsDisabledHost(t *testing.T) {
	dir, cfg, bin, _ := reinstallRig(t)
	cfg.Reinstall.After.Duration = time.Minute
	now := time.Unix(1_000_000, 0)
	ctl := &Controller{dir: dir, beats: map[string]*beat{}, disabled: map[string]bool{"web01": true}, now: func() time.Time { return now }}
	f := &fakeSSH{}
	ctl.EnableReinstall(cfg, f, bin)
	ctl.heartbeat("web01", true)
	ctl.heartbeat("web01", false)
	now = now.Add(time.Hour)
	ctl.checkReinstall()
	ctl.rwg.Wait()
	if f.n() != 0 {
		t.Fatalf("a disabled host was reinstalled: %d", f.n())
	}
}

// The defaults are applied to a copy: the controller's shared config is
// never written from a reinstall's goroutine.
func TestReinstall_DoesNotMutateTheSharedConfig(t *testing.T) {
	dir, cfg, bin, _ := reinstallRig(t)
	cfg.Reinstall.User = ""
	if err := Reinstall(context.Background(), dir, cfg, "web01", &fakeSSH{}, bin); err != nil {
		t.Fatal(err)
	}
	if cfg.Reinstall.User != "" || cfg.Reinstall.After.Duration != 0 {
		t.Fatalf("mutated: %+v", cfg.Reinstall)
	}
}
