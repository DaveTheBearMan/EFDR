package fleet_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/config"
	"xdr/internal/controller"
	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

func start(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client) {
	t.Helper()
	e, c, err := controller.StartEtcd(dir, listen)
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := pki.Hosts(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.Bootstrap(ctx, c, hosts); err != nil {
		t.Fatal(err)
	}
	return e, c
}

// agent is a running client and what it has handed back.
type agent struct {
	c      *fleet.Client
	cache  string
	mu     sync.Mutex
	sets   []*rules.Set
	ins    []incident.Incident
	hunts  []*hunt.Request
	cancel context.CancelFunc
	done   chan struct{}
}

func (a *agent) got() ([]*rules.Set, []incident.Incident) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*rules.Set(nil), a.sets...), append([]incident.Incident(nil), a.ins...)
}

func (a *agent) stop() {
	a.cancel()
	<-a.done
}

func newAgent(t *testing.T, f *fleettest.Fleet, endpoint string) *agent {
	return newAgentAs(t, f, "web01", endpoint)
}

func newAgentAs(t *testing.T, f *fleettest.Fleet, host, endpoint string) *agent {
	t.Helper()
	pub, err := rules.LoadPublic(filepath.Join(f.Bundle(host), "rules.pub"))
	if err != nil {
		t.Fatal(err)
	}
	a := &agent{cache: filepath.Join(t.TempDir(), "rules.json"), done: make(chan struct{})}
	a.c = fleet.New(host, config.Fleet{Endpoints: []string{endpoint}, Dir: f.Bundle(host)}, a.cache, pub)
	fleet.Tune(a.c, 2, 100*time.Millisecond, 300*time.Millisecond)
	return a
}

func (a *agent) run(t *testing.T) *agent {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	go func() {
		defer close(a.done)
		a.c.Run(ctx,
			func(s *rules.Set) { a.mu.Lock(); a.sets = append(a.sets, s); a.mu.Unlock() },
			func(in incident.Incident) { a.mu.Lock(); a.ins = append(a.ins, in); a.mu.Unlock() },
			func(r *hunt.Request) { a.mu.Lock(); a.hunts = append(a.hunts, r); a.mu.Unlock() })
	}()
	t.Cleanup(func() {
		select {
		case <-a.done:
		default:
			a.stop()
		}
	})
	return a
}

func eventually(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %s: %s", within, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func publish(t *testing.T, f *fleettest.Fleet, key ed25519.PrivateKey, version uint64, rs ...rules.Rule) {
	t.Helper()
	for i := range rs {
		rs[i].SetID()
	}
	e, err := rules.Sign(&rules.Set{Version: version, Rules: rs}, key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := rules.Marshal(e)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.Root.Put(ctx, fleet.RulesKey, string(b)); err != nil {
		t.Fatal(err)
	}
}

func signing(t *testing.T, f *fleettest.Fleet) ed25519.PrivateKey {
	key, err := rules.LoadPrivate(filepath.Join(f.Dir, "rules.key"))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func c2(port uint16) rules.Rule {
	return rules.Rule{Kind: "remote", Addr: netip.MustParseAddr("203.0.113.9"), Port: port, Proto: "tcp", From: "db01"}
}

func newFleet(t *testing.T) *fleettest.Fleet {
	f := fleettest.New(t, start, "web01")
	t.Cleanup(f.Stop)
	return f
}

func of(ins []incident.Incident, kind string) (out []incident.Incident) {
	for _, in := range ins {
		if in.Kind == kind {
			out = append(out, in)
		}
	}
	return out
}

func TestClient_ReceivesAndCaches(t *testing.T) {
	f := newFleet(t)
	key := signing(t, f)
	a := newAgent(t, f, f.Listen).run(t)
	publish(t, f, key, 1, c2(4444))
	eventually(t, "rules", time.Second, func() bool { s, _ := a.got(); return len(s) == 1 })
	sets, _ := a.got()
	if sets[0].Version != 1 || len(sets[0].Rules) != 1 {
		t.Fatalf("%+v", sets[0])
	}
	pub, _ := rules.LoadPublic(filepath.Join(f.Bundle("web01"), "rules.pub"))
	fresh := fleet.New("web01", config.Fleet{Endpoints: []string{f.Listen}, Dir: f.Bundle("web01")}, a.cache, pub)
	if s, err := fresh.Cached(); err != nil || s == nil || s.Version != 1 {
		t.Fatalf("cached %+v %v", s, err)
	}
	none := fleet.New("web01", config.Fleet{Endpoints: []string{f.Listen}, Dir: f.Bundle("web01")}, filepath.Join(t.TempDir(), "none.json"), pub)
	if s, err := none.Cached(); s != nil || err != nil {
		t.Fatalf("no cache: %+v %v", s, err)
	}
}

func TestClient_RefusesOlderAndForged(t *testing.T) {
	f := newFleet(t)
	key := signing(t, f)
	a := newAgent(t, f, f.Listen).run(t)
	publish(t, f, key, 2, c2(1), c2(2))
	eventually(t, "v2", time.Second, func() bool { s, _ := a.got(); return len(s) == 1 })
	publish(t, f, key, 1, c2(1))
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	eventually(t, "older refused", 2*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "rules-refused")) == 1 })
	publish(t, f, forger, 3, c2(9))
	eventually(t, "forged refused", 2*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "rules-refused")) == 2 })
	sets, ins := a.got()
	if len(sets) != 1 {
		t.Fatalf("applied %d sets", len(sets))
	}
	if r := of(ins, "rules-refused"); !strings.Contains(r[0].Detail, "older") || !strings.Contains(r[1].Detail, "signature") {
		t.Fatalf("%+v", r)
	}
	pub, _ := rules.LoadPublic(filepath.Join(f.Bundle("web01"), "rules.pub"))
	if s, _ := fleet.New("web01", config.Fleet{}, a.cache, pub).Cached(); s == nil || s.Version != 2 {
		t.Fatalf("cache %+v", s)
	}
	// The same version again, as after a reconnect, is no news.
	publish(t, f, key, 2, c2(1), c2(2))
	time.Sleep(300 * time.Millisecond)
	if sets, ins := a.got(); len(sets) != 1 || len(of(ins, "rules-refused")) != 2 {
		t.Fatalf("same version: %d sets, %+v", len(sets), ins)
	}
}

func TestClient_StartsAboveCache(t *testing.T) {
	f := newFleet(t)
	key := signing(t, f)
	a := newAgent(t, f, f.Listen).run(t)
	publish(t, f, key, 5, c2(1))
	eventually(t, "v5", time.Second, func() bool { s, _ := a.got(); return len(s) == 1 })
	a.stop()
	publish(t, f, key, 4, c2(1))
	b := newAgent(t, f, f.Listen)
	b.cache = a.cache
	pub, _ := rules.LoadPublic(filepath.Join(f.Bundle("web01"), "rules.pub"))
	b.c = fleet.New("web01", config.Fleet{Endpoints: []string{f.Listen}, Dir: f.Bundle("web01")}, a.cache, pub)
	fleet.Tune(b.c, 2, 100*time.Millisecond, 300*time.Millisecond)
	if s, _ := b.c.Cached(); s == nil || s.Version != 5 {
		t.Fatalf("cached %+v", s)
	}
	b.run(t)
	eventually(t, "older than the cache refused", 2*time.Second, func() bool { _, ins := b.got(); return len(of(ins, "rules-refused")) == 1 })
}

func TestClient_HeartbeatPresent(t *testing.T) {
	f := newFleet(t)
	a := newAgent(t, f, f.Listen)
	fleet.Tune(a.c, 10, 100*time.Millisecond, 300*time.Millisecond)
	a.run(t)
	has := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := f.Root.Get(ctx, fleet.Heartbeat("web01"))
		return err == nil && len(r.Kvs) == 1
	}
	eventually(t, "heartbeat", 2*time.Second, has)
	a.stop()
	// Well inside the 10 s lease: stopping revokes it.
	eventually(t, "heartbeat gone", 2*time.Second, func() bool { return !has() })
}

func TestClient_HeartbeatOutlivesLease(t *testing.T) {
	f := newFleet(t)
	newAgent(t, f, f.Listen).run(t) // 2 s lease
	has := func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := f.Root.Get(ctx, fleet.Heartbeat("web01"))
		return err == nil && len(r.Kvs) == 1
	}
	eventually(t, "heartbeat", 2*time.Second, has)
	time.Sleep(2500 * time.Millisecond)
	if !has() {
		t.Fatal("heartbeat expired while running")
	}
}

func TestClient_ProposeAndReport(t *testing.T) {
	f := newFleet(t)
	a := newAgent(t, f, f.Listen)
	r := c2(4444)
	r.SetID()
	a.c.Propose([]rules.Rule{r}) // queued before the client runs
	a.run(t)
	a.c.Report(incident.Incident{Kind: "egress", Action: "killed"})
	a.c.Report(incident.Incident{Kind: "egress", Action: "killed"})
	count := func(prefix string) int {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		resp, err := f.Root.Get(ctx, prefix, clientv3.WithPrefix())
		if err != nil {
			return -1
		}
		return len(resp.Kvs)
	}
	eventually(t, "proposal", 2*time.Second, func() bool { return count(fleet.Proposed("web01")+r.ID) == 1 })
	eventually(t, "two incidents", 2*time.Second, func() bool { return count(fleet.Incidents("web01")) == 2 })
}

func TestClient_UnreachableDoesNotBlock(t *testing.T) {
	f := newFleet(t)
	a := newAgent(t, f, "127.0.0.1:1").run(t)
	start := time.Now()
	for range 1000 {
		a.c.Propose([]rules.Rule{c2(1)})
		a.c.Report(incident.Incident{Kind: "egress"})
	}
	// A blocking call would wait out a dial; 1s leaves room for -race under load.
	if d := time.Since(start); d > time.Second {
		t.Fatalf("2000 calls took %s", d)
	}
	eventually(t, "fleet alert", 3*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "fleet")) == 1 })
	time.Sleep(500 * time.Millisecond)
	if _, ins := a.got(); len(of(ins, "fleet")) != 1 {
		t.Fatalf("fleet alerts %d", len(of(ins, "fleet")))
	}
}

func TestClient_Reconnects(t *testing.T) {
	f := newFleet(t)
	key := signing(t, f)
	a := newAgent(t, f, f.Listen).run(t)
	eventually(t, "connected", 2*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := f.Root.Get(ctx, fleet.Heartbeat("web01"))
		return err == nil && len(r.Kvs) == 1
	})
	f.Stop()
	eventually(t, "unreachable", 5*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "fleet")) == 1 })
	f.Start(t)
	publish(t, f, key, 1, c2(4444))
	eventually(t, "reconnected", 10*time.Second, func() bool {
		_, ins := a.got()
		fl := of(ins, "fleet")
		return len(fl) == 2 && strings.Contains(fl[1].Detail, "reconnected")
	})
	eventually(t, "rules after reconnect", 5*time.Second, func() bool { s, _ := a.got(); return len(s) == 1 })
}

// A connection that answers and then fails, again and again, is as good
// as none: the alert still comes.
func TestClient_FlappingAlerts(t *testing.T) {
	f := newFleet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The rule set can be read, but every heartbeat is refused.
	if _, err := f.Root.RoleRevokePermission(ctx, "host-web01", fleet.Heartbeat("web01"), ""); err != nil {
		t.Fatal(err)
	}
	// As in production, the alert threshold is longer than the backoff.
	a := newAgent(t, f, f.Listen)
	fleet.Tune(a.c, 2, 100*time.Millisecond, 1500*time.Millisecond)
	a.run(t)
	eventually(t, "fleet alert", 5*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "fleet")) >= 1 })
	if _, ins := a.got(); strings.Contains(of(ins, "fleet")[0].Detail, "reconnected") {
		t.Fatalf("%+v", of(ins, "fleet"))
	}
}

// Stopping never waits on a dial that hangs.
func TestClient_StopDuringDial(t *testing.T) {
	f := newFleet(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0") // accepts, never speaks TLS
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a := newAgent(t, f, ln.Addr().String()).run(t)
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	a.cancel()
	<-a.done
	if d := time.Since(start); d > time.Second {
		t.Fatalf("stop took %s", d)
	}
}

func TestClient_HuntRoundTrip(t *testing.T) {
	f := fleettest.New(t, start, "web01", "db01")
	t.Cleanup(f.Stop)
	web := newAgentAs(t, f, "web01", f.Listen).run(t)
	db := newAgentAs(t, f, "db01", f.Listen).run(t)
	eventually(t, "both up", 3*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := f.Root.Get(ctx, fleet.HeartbeatAll, clientv3.WithPrefix())
		return err == nil && len(r.Kvs) == 2
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.Root.Put(ctx, fleet.Hunt("web01")+"junk", "not json"); err != nil {
		t.Fatal(err)
	}
	ioc := hunt.IOC{Cron: []string{"curl x | sh"}}
	req := &hunt.Request{ID: hunt.ID(ioc), From: "web01", Time: time.Now().UTC().Truncate(time.Second), IOC: ioc}
	// A hunt put under one host's key that claims another is ignored.
	liar := *req
	liar.From = "mail01"
	b, _ := json.Marshal(liar)
	if _, err := f.Root.Put(ctx, fleet.Hunt("web01")+"liar", string(b)); err != nil {
		t.Fatal(err)
	}
	web.c.PutHunt(req)
	eventually(t, "db01 got the hunt", 2*time.Second, func() bool {
		db.mu.Lock()
		defer db.mu.Unlock()
		return len(db.hunts) == 1
	})
	db.mu.Lock()
	got := db.hunts[0]
	db.mu.Unlock()
	if !reflect.DeepEqual(got, req) {
		t.Fatalf("got %+v, want %+v", got, req)
	}
	r, err := f.Root.Get(ctx, fleet.Hunt("web01")+req.ID)
	if err != nil || len(r.Kvs) != 1 || r.Kvs[0].Lease == 0 {
		t.Fatalf("hunt key %+v %v", r, err)
	}
	time.Sleep(200 * time.Millisecond)
	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.hunts) != 1 {
		t.Fatalf("%d hunts", len(db.hunts))
	}
}

func TestClient_OfferAndEnvelope(t *testing.T) {
	f := newFleet(t)
	key := signing(t, f)
	a := newAgent(t, f, "127.0.0.1:1")
	env := func(k ed25519.PrivateKey, v uint64) []byte {
		r := c2(uint16(4000 + v))
		r.SetID()
		e, err := rules.Sign(&rules.Set{Version: v, Rules: []rules.Rule{r}}, k)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := rules.Marshal(e)
		return b
	}
	// Before Run: verified and cached only.
	if !a.c.Offer(env(key, 2)) {
		t.Fatal("v2 not taken before run")
	}
	if raw, v := a.c.Envelope(); v != 2 || !bytes.Equal(raw, env(key, 2)) {
		t.Fatalf("envelope v%d", v)
	}
	a.run(t)
	// Run has started once it says etcd is out of reach.
	eventually(t, "run started", 3*time.Second, func() bool { _, ins := a.got(); return len(of(ins, "fleet")) == 1 })
	if !a.c.Offer(env(key, 3)) {
		t.Fatal("v3 not taken")
	}
	eventually(t, "v3 applied", time.Second, func() bool { sets, _ := a.got(); return len(sets) == 1 && sets[0].Version == 3 })
	cached, err := a.c.Cached()
	if err != nil || cached == nil || cached.Version != 3 {
		t.Fatalf("cache %+v %v", cached, err)
	}
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	if a.c.Offer(env(key, 1)) || a.c.Offer(env(forger, 9)) || a.c.Offer(env(key, 3)) {
		t.Fatal("older, forged or same set taken")
	}
	eventually(t, "two refusals", time.Second, func() bool { _, ins := a.got(); return len(of(ins, "rules-refused")) == 2 })
	if _, v := a.c.Envelope(); v != 3 {
		t.Fatalf("envelope v%d", v)
	}
}
