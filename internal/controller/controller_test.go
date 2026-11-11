package controller

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/incident"
	"xdr/internal/rules"
)

const baseSum = "cd34000000000000000000000000000000000000000000000000000000000000"

func sumN(n int) string {
	return strings.Repeat("0", 62) + string("0123456789abcdef"[n/16]) + string("0123456789abcdef"[n%16])
}

// rig is a running controller over a test etcd.
type rig struct {
	f      *fleettest.Fleet
	ctl    *Controller
	mu     sync.Mutex
	lines  []incident.Incident
	cancel context.CancelFunc
	done   chan error
}

func (r *rig) seen() []incident.Incident {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]incident.Incident(nil), r.lines...)
}

// run starts a controller on f, tuned for tests.
func run(t *testing.T, f *fleettest.Fleet, tune func(*Controller)) *rig {
	t.Helper()
	key, err := rules.LoadPrivate(filepath.Join(f.Dir, "rules.key"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := incident.Open(filepath.Join(t.TempDir(), "incidents.jsonl"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{f: f, done: make(chan error, 1)}
	log.OnWrite = func(in incident.Incident) {
		r.mu.Lock()
		r.lines = append(r.lines, in)
		r.mu.Unlock()
	}
	g := rules.Guard{
		Baseline: func(s string) bool { return s == baseSum },
		Protect:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	ctl, err := New(f.Dir, f.Root, g, key, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl.tick, ctl.silentAfter = 20*time.Millisecond, time.Hour
	if tune != nil {
		tune(ctl)
	}
	r.ctl = ctl
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- ctl.Run(ctx) }()
	t.Cleanup(func() {
		r.stop()
		log.Close()
	})
	return r
}

func (r *rig) stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.done
		r.cancel = nil
	}
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within 3s: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func propose(t *testing.T, f *fleettest.Fleet, host string, r rules.Rule) string {
	t.Helper()
	r.SetID()
	b, _ := json.Marshal(r)
	key := fleet.Proposed(host) + r.ID
	if _, err := hostClient(t, f, host).Put(ctx5(t), key, string(b)); err != nil {
		t.Fatal(err)
	}
	return key
}

func remote(addr string, port uint16) rules.Rule {
	return rules.Rule{Kind: "remote", Addr: netip.MustParseAddr(addr), Port: port, Proto: "tcp", From: "web01"}
}

// published is the rule set in etcd, verified.
func published(t *testing.T, f *fleettest.Fleet) *rules.Set {
	t.Helper()
	resp, err := f.Root.Get(ctx5(t), fleet.RulesKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Kvs) == 0 {
		return nil
	}
	e, err := rules.Unmarshal(resp.Kvs[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rules.LoadPublic(filepath.Join(f.Dir, "rules.pub"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := rules.Open(e, pub)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func version(t *testing.T, f *fleettest.Fleet) uint64 {
	if s := published(t, f); s != nil {
		return s.Version
	}
	return 0
}

func gone(t *testing.T, f *fleettest.Fleet, key string) bool {
	resp, err := f.Root.Get(ctx5(t), key)
	return err == nil && len(resp.Kvs) == 0
}

func kinds(ins []incident.Incident, kind string) (out []incident.Incident) {
	for _, in := range ins {
		if in.Kind == kind {
			out = append(out, in)
		}
	}
	return out
}

func TestPromote_Valid(t *testing.T) {
	f := newFleet(t, "web01")
	r := run(t, f, nil)
	key := propose(t, f, "web01", remote("203.0.113.9", 4444))
	eventually(t, "version 1", func() bool { return version(t, f) == 1 })
	s := published(t, f)
	if len(s.Rules) != 1 || s.Rules[0].Addr != netip.MustParseAddr("203.0.113.9") || s.Rules[0].From != "web01" || s.Issued.IsZero() {
		t.Fatalf("%+v", s)
	}
	eventually(t, "proposal deleted", func() bool { return gone(t, f, key) })
	eventually(t, "rule-promoted line", func() bool { return len(kinds(r.seen(), "rule-promoted")) == 1 })
	if in := kinds(r.seen(), "rule-promoted")[0]; in.Host != "web01" || in.Remote == nil || in.Remote.Port != 4444 {
		t.Fatalf("%+v", in)
	}
}

func TestPromote_Rejected(t *testing.T) {
	f := newFleet(t, "web01")
	r := run(t, f, nil)
	key := propose(t, f, "web01", rules.Rule{Kind: "hash", SHA256: baseSum, Exe: "/tmp/sh"})
	eventually(t, "rule-rejected line", func() bool { return len(kinds(r.seen(), "rule-rejected")) == 1 })
	if in := kinds(r.seen(), "rule-rejected")[0]; !strings.Contains(in.Detail, "baseline hash") || in.Host != "web01" {
		t.Fatalf("%+v", in)
	}
	eventually(t, "proposal deleted", func() bool { return gone(t, f, key) })
	if v := version(t, f); v != 0 {
		t.Fatalf("version %d", v)
	}
}

func TestPromote_BadValue(t *testing.T) {
	f := newFleet(t, "web01")
	r := run(t, f, nil)
	c := hostClient(t, f, "web01")
	ok := remote("203.0.113.9", 4444)
	ok.SetID()
	b, _ := json.Marshal(ok)
	for key, val := range map[string]string{
		fleet.Proposed("web01") + "junk":             "not json",
		fleet.Proposed("web01") + "0000000000000000": string(b), // id is not the rule's
		fleet.Proposed("web01") + "big":              strings.Repeat("x", 17<<10),
	} {
		if _, err := c.Put(ctx5(t), key, val); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "three rejections", func() bool { return len(kinds(r.seen(), "rule-rejected")) == 3 })
	if v := version(t, f); v != 0 {
		t.Fatalf("version %d", v)
	}
}

func TestPromote_Duplicate(t *testing.T) {
	f := newFleet(t, "web01", "db01")
	run(t, f, nil)
	propose(t, f, "web01", remote("203.0.113.9", 4444))
	eventually(t, "version 1", func() bool { return version(t, f) == 1 })
	key := propose(t, f, "db01", remote("203.0.113.9", 4444))
	eventually(t, "duplicate deleted", func() bool { return gone(t, f, key) })
	if v := version(t, f); v != 1 {
		t.Fatalf("version %d", v)
	}
}

func TestPromote_FromSpoof(t *testing.T) {
	f := newFleet(t, "web01", "db01")
	run(t, f, nil)
	rl := remote("203.0.113.9", 4444)
	rl.From = "db01"
	propose(t, f, "web01", rl)
	eventually(t, "version 1", func() bool { return version(t, f) == 1 })
	if s := published(t, f); s.Rules[0].From != "web01" {
		t.Fatalf("from %q", s.Rules[0].From)
	}
}

func TestPromote_HostCap(t *testing.T) {
	f := newFleet(t, "web01", "db01")
	r := run(t, f, func(c *Controller) { c.hostCap = 3 })
	for i := range 4 {
		propose(t, f, "web01", rules.Rule{Kind: "hash", SHA256: sumN(i)})
		if i < 3 {
			eventually(t, "promoted", func() bool { return version(t, f) == uint64(i+1) })
		}
	}
	eventually(t, "host limit", func() bool {
		rej := kinds(r.seen(), "rule-rejected")
		return len(rej) == 1 && strings.Contains(rej[0].Detail, "host limit")
	})
	propose(t, f, "db01", rules.Rule{Kind: "hash", SHA256: sumN(9)})
	eventually(t, "another host is not capped", func() bool { return version(t, f) == 4 })
}

func TestPromote_VersionSurvivesRestart(t *testing.T) {
	f := newFleet(t, "web01")
	r := run(t, f, nil)
	propose(t, f, "web01", remote("203.0.113.9", 1))
	eventually(t, "v1", func() bool { return version(t, f) == 1 })
	propose(t, f, "web01", remote("203.0.113.9", 2))
	eventually(t, "v2", func() bool { return version(t, f) == 2 })
	r.stop()
	f.Stop()
	f.Start(t)
	run(t, f, nil)
	propose(t, f, "web01", remote("203.0.113.9", 3))
	eventually(t, "v3", func() bool { return version(t, f) == 3 })
	if n := len(published(t, f).Rules); n != 3 {
		t.Fatalf("%d rules", n)
	}
}

func TestRevoke(t *testing.T) {
	f := newFleet(t, "web01")
	run(t, f, nil)
	propose(t, f, "web01", remote("203.0.113.9", 1))
	eventually(t, "v1", func() bool { return version(t, f) == 1 })
	propose(t, f, "web01", remote("203.0.113.9", 2))
	eventually(t, "v2", func() bool { return version(t, f) == 2 })
	id := published(t, f).Rules[0].ID

	// A second controller, as `xdr rules revoke` is, revokes while the
	// first one runs; the first one's next write still goes through.
	key, _ := rules.LoadPrivate(filepath.Join(f.Dir, "rules.key"))
	other, err := New(f.Dir, f.Root, rules.Guard{}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Revoke(ctx5(t), id); err != nil {
		t.Fatal(err)
	}
	s := published(t, f)
	if s.Version != 3 || len(s.Rules) != 1 || s.Rules[0].ID == id {
		t.Fatalf("%+v", s)
	}
	if err := other.Revoke(ctx5(t), "nope"); err == nil || !strings.Contains(err.Error(), "no rule nope") {
		t.Fatalf("got %v", err)
	}
	propose(t, f, "web01", remote("203.0.113.9", 3))
	eventually(t, "v4 after the revoke", func() bool { return version(t, f) == 4 })
	if n := len(published(t, f).Rules); n != 2 {
		t.Fatalf("%d rules", n)
	}
}

func TestIncidents_Ingested(t *testing.T) {
	f := newFleet(t, "web01")
	r := run(t, f, nil)
	b, _ := json.Marshal(incident.Incident{Time: time.Now(), Host: "evil", Kind: "egress", Action: "killed", Detail: "x"})
	key := fleet.Incidents("web01") + "1"
	if _, err := hostClient(t, f, "web01").Put(ctx5(t), key, string(b)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "logged", func() bool { return len(kinds(r.seen(), "egress")) == 1 })
	if in := kinds(r.seen(), "egress")[0]; in.Host != "web01" {
		t.Fatalf("host %q", in.Host)
	}
	eventually(t, "deleted", func() bool { return gone(t, f, key) })
}

func TestHeartbeat_SilentAndBack(t *testing.T) {
	f := newFleet(t, "web01", "db01")
	r := run(t, f, func(c *Controller) { c.silentAfter = 300 * time.Millisecond })
	c := hostClient(t, f, "web01")
	beat := func() clientv3.LeaseID {
		l, err := c.Grant(ctx5(t), 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Put(ctx5(t), fleet.Heartbeat("web01"), "{}", clientv3.WithLease(l.ID)); err != nil {
			t.Fatal(err)
		}
		return l.ID
	}
	l := beat()
	eventually(t, "db01 silent", func() bool {
		s := kinds(r.seen(), "agent-silent")
		return len(s) == 1 && s[0].Host == "db01"
	})
	if _, err := c.Revoke(ctx5(t), l); err != nil {
		t.Fatal(err)
	}
	eventually(t, "web01 silent", func() bool { return len(kinds(r.seen(), "agent-silent")) == 2 })
	beat()
	eventually(t, "web01 back", func() bool {
		b := kinds(r.seen(), "agent-back")
		return len(b) == 1 && b[0].Host == "web01"
	})
	time.Sleep(200 * time.Millisecond)
	if n := len(kinds(r.seen(), "agent-silent")); n != 2 {
		t.Fatalf("silent reported %d times", n)
	}
}
