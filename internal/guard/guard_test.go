package guard

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xdr/internal/install"
)

type fake struct {
	mu     sync.Mutex
	cmds   []string
	active map[string]string
}

func (f *fake) run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, cmd)
	if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		if s, ok := f.active[args[1]]; ok {
			return []byte(s + "\n"), nil
		}
		return []byte("active\n"), nil
	}
	return nil, nil
}

func (f *fake) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func installed(t *testing.T) install.Layout {
	t.Helper()
	l := install.DefaultLayout()
	l.Root = t.TempDir()
	for p, c := range map[string]string{l.Config: "{}\n", l.Config + ".sig": "c2ln\n", l.FleetDir + "/ca.pem": "CA\n"} {
		full := filepath.Join(l.Root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o600)
	}
	bin := filepath.Join(t.TempDir(), "xdr")
	os.WriteFile(bin, []byte("#!/bin/sh\necho agent\n"), 0o755)
	if _, err := install.Install(l, (&fake{}).run, bin); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestGuard_StartsTheOtherGuard(t *testing.T) {
	l := installed(t)
	f := &fake{active: map[string]string{"xdr-guard-b.service": "inactive"}}
	var said []string
	Tick(l, f.run, "xdr-guard-b.service", func(s string) { said = append(said, s) })
	if f.count("systemctl start xdr-guard-b.service") != 1 {
		t.Fatalf("started %d times: %v", f.count("systemctl start xdr-guard-b.service"), f.cmds)
	}
	if len(said) != 1 || !strings.Contains(said[0], "xdr-guard-b.service") {
		t.Fatalf("said %v", said)
	}
	// A quiet tick says nothing and starts nothing.
	g := &fake{}
	said = nil
	Tick(l, g.run, "xdr-guard-b.service", func(s string) { said = append(said, s) })
	if len(said) != 0 || g.count("systemctl start") != 0 {
		t.Fatalf("a quiet tick: %v %v", said, g.cmds)
	}
}

func TestGuard_RestoresADeletedUnitFile(t *testing.T) {
	l := installed(t)
	unit := filepath.Join(l.Root, "/etc/systemd/system/xdr-guard-b.service")
	os.Remove(unit)
	f := &fake{active: map[string]string{"xdr-guard-b.service": "inactive"}}
	var said []string
	Tick(l, f.run, "xdr-guard-b.service", func(s string) { said = append(said, s) })
	b, err := os.ReadFile(unit)
	if err != nil || !strings.Contains(string(b), "guard --watch xdr-guard-a.service") {
		t.Fatalf("the unit was not restored: %q %v", b, err)
	}
	if f.count("systemctl daemon-reload") != 1 || f.count("systemctl start xdr-guard-b.service") != 1 {
		t.Fatalf("%v", f.cmds)
	}
	if !strings.Contains(strings.Join(said, "|"), "restored /etc/systemd/system/xdr-guard-b.service") {
		t.Fatalf("said %v", said)
	}
}

func TestGuard_StopsWithTheContext(t *testing.T) {
	l := installed(t)
	f := &fake{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, l, f.run, "xdr-guard-b.service", 10*time.Millisecond, func(string) {}); close(done) }()
	for i := 0; i < 200 && f.count("systemctl is-active xdr-agent.service") < 3; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if f.count("systemctl is-active xdr-agent.service") < 3 {
		t.Fatal("the loop does not tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("still running after the context ended")
	}
}

func TestGuard_StartsTheOtherWithoutWaiting(t *testing.T) {
	l := installed(t)
	f := &fake{active: map[string]string{"xdr-guard-b.service": "inactive"}}
	Tick(l, func(name string, args ...string) ([]byte, error) {
		// ensure sees b as active; only the guard's own look sees it down
		if name == "systemctl" && len(args) == 2 && args[0] == "is-active" && args[1] == "xdr-guard-b.service" && f.count("systemctl is-active xdr-guard-b.service") == 0 {
			f.run(name, args...)
			return []byte("active\n"), nil
		}
		return f.run(name, args...)
	}, "xdr-guard-b.service", func(string) {})
	n := 0
	for _, c := range f.cmds {
		if strings.HasPrefix(c, "systemctl start") {
			n++
			if !strings.Contains(c, "--no-block") {
				t.Fatalf("a start that waits: %q", c)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%v", f.cmds)
	}
}
