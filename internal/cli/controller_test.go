package cli

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/console"
	"xdr/internal/controller"
	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/rules"
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

func TestRules_ListRevokeCLI(t *testing.T) {
	f := fleettest.New(t, func(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client) {
		e, c, err := controller.StartEtcd(dir, listen)
		if err != nil {
			t.Fatal(err)
		}
		return e, c
	})
	defer f.Stop()
	if err := os.WriteFile(filepath.Join(f.Dir, "controller.json"), []byte(`{"listen": "`+f.Listen+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := rules.LoadPrivate(filepath.Join(f.Dir, "rules.key"))
	if err != nil {
		t.Fatal(err)
	}
	a := rules.Rule{Kind: "remote", Addr: netip.MustParseAddr("203.0.113.9"), Port: 4444, Proto: "tcp", From: "web01"}
	b := rules.Rule{Kind: "hash", SHA256: strings.Repeat("ab", 32), Exe: "/tmp/.x\x1b[2J", From: "db01"}
	u := rules.Rule{Kind: "unit", Unit: "evil.service", SHA256: strings.Repeat("cd", 32), From: "web01"}
	c := rules.Rule{Kind: "cron", Command: "curl -s x | sh", From: "web01"}
	a.SetID()
	b.SetID()
	u.SetID()
	c.SetID()
	e, _ := rules.Sign(&rules.Set{Version: 4, Rules: []rules.Rule{a, b, u, c}}, key)
	raw, _ := rules.Marshal(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.Root.Put(ctx, fleet.RulesKey, string(raw)); err != nil {
		t.Fatal(err)
	}

	var so, se bytes.Buffer
	if code := Run([]string{"rules", "list", "--dir", f.Dir}, &so, &se); code != 0 {
		t.Fatalf("list: %d %s", code, se.String())
	}
	out := so.String()
	for _, want := range []string{"version 4", a.ID + " remote 203.0.113.9:4444/tcp web01", b.ID + " hash " + b.SHA256,
		u.ID + " unit evil.service@" + u.SHA256 + " web01", c.ID + ` cron "curl -s x | sh" web01`} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.ContainsRune(out, 0x1b) {
		t.Error("raw escape in the listing")
	}
	so.Reset()
	if code := Run([]string{"rules", "revoke", "--dir", f.Dir, a.ID}, &so, &se); code != 0 {
		t.Fatalf("revoke: %d %s", code, se.String())
	}
	so.Reset()
	Run([]string{"rules", "list", "--dir", f.Dir}, &so, &se)
	if out := so.String(); strings.Contains(out, a.ID) || !strings.Contains(out, "version 5") {
		t.Fatalf("after revoke:\n%s", out)
	}
	se.Reset()
	if code := Run([]string{"rules", "revoke", "--dir", f.Dir, "nope"}, &so, &se); code != 2 || !strings.Contains(se.String(), "no rule nope") {
		t.Fatalf("unknown id: %d %q", code, se.String())
	}
}

func TestDisableHostCLI(t *testing.T) {
	f := fleettest.New(t, func(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client) {
		e, c, err := controller.StartEtcd(dir, listen)
		if err != nil {
			t.Fatal(err)
		}
		return e, c
	}, "web01")
	defer f.Stop()
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "disable-host", "--dir", f.Dir, "--endpoint", f.Listen, "--host", "web01"}, &so, &se); code != 0 {
		t.Fatalf("%d %s", code, se.String())
	}
	if !strings.Contains(so.String(), "disabled web01") {
		t.Fatalf("%q", so.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if resp, err := f.Root.Get(ctx, fleet.DisabledAll+"web01"); err != nil || len(resp.Kvs) != 1 {
		t.Fatalf("%v %v", resp, err)
	}
	if code := Run([]string{"controller", "disable-host", "--dir", f.Dir, "--host", "nope"}, &so, &se); code == 0 {
		t.Fatal("an unenrolled host was disabled")
	}
}

func TestConsolePasswordCLI(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ctl")
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "init", "--dir", dir, "--name", "127.0.0.1"}, &so, &se); code != 0 {
		t.Fatal(se.String())
	}
	stdin := func(s string) {
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
	stdin("short\n")
	if code := Run([]string{"controller", "console-password", "--dir", dir}, &so, &se); code == 0 || !strings.Contains(se.String(), "at least 12") {
		t.Fatalf("a short password: %d %q", code, se.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "console.json")); err == nil {
		t.Fatal("console.json written for a refused password")
	}
	se.Reset()
	stdin("a long enough passphrase\n")
	if code := Run([]string{"controller", "console-password", "--dir", dir}, &so, &se); code != 0 {
		t.Fatalf("exit %d %q", code, se.String())
	}
	st, err := os.Stat(filepath.Join(dir, "console.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("console.json: %v %v", st, err)
	}
	if !console.CheckPassword(dir, "a long enough passphrase") || console.CheckPassword(dir, "a long enough passphrase\n") {
		t.Fatal("the stored hash does not verify the password given (without its newline)")
	}
}

func TestControllerConfig_Console(t *testing.T) {
	p := filepath.Join(t.TempDir(), "controller.json")
	os.WriteFile(p, []byte(`{"listen":"127.0.0.1:2379","console":{"listen":"127.0.0.1:8443"}}`), 0o600)
	c, err := controller.LoadConfig(p)
	if err != nil || c.Console == nil || c.Console.Listen != "127.0.0.1:8443" {
		t.Fatalf("%+v %v", c, err)
	}
	os.WriteFile(p, []byte(`{"listen":"127.0.0.1:2379","console":{"listen":"nonsense"}}`), 0o600)
	if _, err := controller.LoadConfig(p); err == nil {
		t.Fatal("a bad console listen address was accepted")
	}
	os.WriteFile(p, []byte(`{"listen":"127.0.0.1:2379"}`), 0o600)
	if c, err = controller.LoadConfig(p); err != nil || c.Console != nil {
		t.Fatalf("no console: %+v %v", c, err)
	}
}

func TestExampleControllerConfigLoads(t *testing.T) {
	c, err := controller.LoadConfig("../../deploy/controller.example.json")
	if err != nil || c.Console == nil || len(c.GrayUsers) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
}
