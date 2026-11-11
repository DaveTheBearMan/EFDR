package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/pki"
)

// fakeRules holds a "set" as the text "v<N>", and takes only newer ones.
type fakeRules struct {
	mu    sync.Mutex
	v     uint64
	taken int
}

func (f *fakeRules) Offer(b []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, err := strconv.ParseUint(strings.TrimPrefix(string(b), "v"), 10, 64)
	if err != nil || !strings.HasPrefix(string(b), "v") || n <= f.v {
		return false
	}
	f.v, f.taken = n, f.taken+1
	return true
}

func (f *fakeRules) Envelope() ([]byte, uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.v == 0 {
		return nil, 0
	}
	return []byte(fmt.Sprintf("v%d", f.v)), f.v
}

func (f *fakeRules) state() (uint64, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v, f.taken
}

type node struct {
	m      *Mesh
	rules  *fakeRules
	addr   netip.AddrPort
	mu     sync.Mutex
	hunts  []*hunt.Request
	ins    []incident.Incident
	cancel context.CancelFunc
	done   chan error
}

func (n *node) got() ([]*hunt.Request, []incident.Incident) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*hunt.Request(nil), n.hunts...), append([]incident.Incident(nil), n.ins...)
}

func (n *node) start(t *testing.T) *node {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel, n.done = cancel, make(chan error, 1)
	go func() { n.done <- n.m.Run(ctx) }()
	t.Cleanup(n.stop)
	waitListen(t, n.addr)
	return n
}

func (n *node) stop() {
	if n.cancel != nil {
		n.cancel()
		<-n.done
		n.cancel = nil
	}
}

func waitListen(t *testing.T, a netip.AddrPort) {
	t.Helper()
	for range 200 {
		if c, err := net.Dial("tcp", a.String()); err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never listened", a)
}

// rig is a CA with hosts enrolled, and a port free on 127.0.0.1.
type rig struct {
	dir, port string
	bundles   map[string]string
}

func newRig(t *testing.T, hosts ...string) *rig {
	t.Helper()
	r := &rig{dir: filepath.Join(t.TempDir(), "ctl"), bundles: map[string]string{}}
	if err := pki.Init(r.dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		out := filepath.Join(t.TempDir(), h)
		if err := pki.Enroll(r.dir, h, out); err != nil {
			t.Fatal(err)
		}
		r.bundles[h] = out
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, r.port, _ = net.SplitHostPort(ln.Addr().String())
	ln.Close()
	return r
}

func (r *rig) tls(t *testing.T, host string) (*tls.Config, *tls.Config) {
	t.Helper()
	b := r.bundles[host]
	s, c, err := pki.PeerTLS(filepath.Join(b, "ca.pem"), filepath.Join(b, "host.pem"), filepath.Join(b, "host-key.pem"), host)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

// node is host listening on 127.0.0.<ip>, peered with the others named.
func (r *rig) node(t *testing.T, host string, ip int, peers ...int) *node {
	t.Helper()
	ap := func(i int) netip.AddrPort { return netip.MustParseAddrPort(fmt.Sprintf("127.0.0.%d:%s", i, r.port)) }
	n := &node{rules: &fakeRules{}, addr: ap(ip)}
	srv, cli := r.tls(t, host)
	cfg := Config{Host: host, Listen: n.addr, ServerTLS: srv, ClientTLS: cli, Rules: n.rules,
		OnHunt:     func(h *hunt.Request, _ netip.Addr) { n.mu.Lock(); n.hunts = append(n.hunts, h); n.mu.Unlock() },
		OnIncident: func(in incident.Incident) { n.mu.Lock(); n.ins = append(n.ins, in); n.mu.Unlock() },
	}
	for _, p := range peers {
		cfg.Peers = append(cfg.Peers, ap(p))
	}
	n.m = New(cfg)
	Tune(n.m, 50*time.Millisecond, 400*time.Millisecond)
	return n
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

func req(cmd string) *hunt.Request {
	ioc := hunt.IOC{Cron: []string{cmd}}
	return &hunt.Request{ID: hunt.ID(ioc), From: "a", IOC: ioc}
}

func kinds(ins []incident.Incident, kind string) (out []incident.Incident) {
	for _, in := range ins {
		if in.Kind == kind {
			out = append(out, in)
		}
	}
	return out
}

func TestMesh_RulesSpread(t *testing.T) {
	r := newRig(t, "a", "b")
	a, b := r.node(t, "a", 2, 3), r.node(t, "b", 3, 2)
	a.rules.v, b.rules.v = 2, 1
	a.start(t)
	b.start(t)
	eventually(t, "b holds v2", time.Second, func() bool { v, _ := b.rules.state(); return v == 2 })
	if v, taken := a.rules.state(); v != 2 || taken != 0 {
		t.Fatalf("a v%d, took %d", v, taken)
	}
	// A newer set pushed at once.
	a.rules.Offer([]byte("v5"))
	a.m.PushRules()
	eventually(t, "b holds v5", time.Second, func() bool { v, _ := b.rules.state(); return v == 5 })
}

func TestMesh_HuntRelayed(t *testing.T) {
	r := newRig(t, "a", "b", "c")
	a, b, c := r.node(t, "a", 2, 3), r.node(t, "b", 3, 2, 4), r.node(t, "c", 4, 3)
	a.start(t)
	b.start(t)
	c.start(t)
	a.m.PushHunt(req("curl x | sh"), netip.Addr{})
	eventually(t, "c got it via b", time.Second, func() bool { h, _ := c.got(); return len(h) == 1 })
	time.Sleep(200 * time.Millisecond)
	ha, _ := a.got()
	hb, _ := b.got()
	hc, _ := c.got()
	if len(ha) != 0 || len(hb) != 1 || len(hc) != 1 {
		t.Fatalf("a %d, b %d, c %d", len(ha), len(hb), len(hc))
	}
}

func TestMesh_ThreePeersNoLoop(t *testing.T) {
	r := newRig(t, "a", "b", "c")
	a, b, c := r.node(t, "a", 2, 3, 4), r.node(t, "b", 3, 2, 4), r.node(t, "c", 4, 2, 3)
	for _, n := range []*node{a, b, c} {
		n.rules.v = 1
		n.start(t)
	}
	a.rules.Offer([]byte("v2"))
	a.m.PushRules()
	a.m.PushHunt(req("curl x | sh"), netip.Addr{})
	eventually(t, "all hold v2", time.Second, func() bool {
		vb, _ := b.rules.state()
		vc, _ := c.rules.state()
		return vb == 2 && vc == 2
	})
	eventually(t, "b and c hunted", time.Second, func() bool {
		hb, _ := b.got()
		hc, _ := c.got()
		return len(hb) == 1 && len(hc) == 1
	})
	time.Sleep(150 * time.Millisecond)
	before := a.m.huntsIn.Load() + b.m.huntsIn.Load() + c.m.huntsIn.Load()
	time.Sleep(200 * time.Millisecond) // 4 beats
	after := a.m.huntsIn.Load() + b.m.huntsIn.Load() + c.m.huntsIn.Load()
	ha, _ := a.got()
	hb, _ := b.got()
	hc, _ := c.got()
	_, tb := b.rules.state()
	_, tc := c.rules.state()
	if after != before || len(ha) != 0 || len(hb) != 1 || len(hc) != 1 || tb != 1 || tc != 1 {
		t.Fatalf("hunt posts %d→%d; hunts a%d b%d c%d; sets taken b%d c%d", before, after, len(ha), len(hb), len(hc), tb, tc)
	}
}

func TestMesh_HostilePeer(t *testing.T) {
	r := newRig(t, "a", "b", "x")
	a := r.node(t, "a", 2, 3)
	a.rules.v = 3
	a.start(t)
	url := "https://" + a.addr.String()
	_, bcli := r.tls(t, "b")
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: bcli}}

	// A cert from another CA.
	other := newRig(t, "b")
	_, ocli := other.tls(t, "b")
	if _, err := (&http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: ocli}}).Get(url + "/rules"); err == nil {
		t.Error("another CA's cert got in")
	}
	// Plain HTTP reaches no handler.
	if resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + a.addr.String() + "/rules"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("plain http: %d", resp.StatusCode)
		}
	}
	post := func(path string, body []byte) int {
		resp, err := cl.Post(url+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// Older and malformed sets are offered and refused; the set holds.
	post("/rules", []byte("v2"))
	post("/rules", []byte("forged"))
	if v, taken := a.rules.state(); v != 3 || taken != 0 {
		t.Fatalf("v%d, took %d", v, taken)
	}
	if code := post("/rules", bytes.Repeat([]byte("x"), 3<<20)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("3 MiB: %d", code)
	}
	bad := req("x")
	bad.ID = "0123456789abcdef"
	b, _ := json.Marshal(bad)
	if code := post("/hunt", b); code != http.StatusBadRequest {
		t.Errorf("bad hunt: %d", code)
	}
	time.Sleep(time.Second) // a fresh rate window
	limited := 0
	for i := range 100 {
		b, _ := json.Marshal(req(fmt.Sprintf("cmd %d", i)))
		if post("/hunt", b) == http.StatusTooManyRequests {
			limited++
		}
	}
	if h, _ := a.got(); limited == 0 || len(h) > 20 {
		t.Fatalf("%d limited, %d hunts", limited, len(h))
	}
}

func TestMesh_PeerSilent(t *testing.T) {
	r := newRig(t, "a", "b")
	a, b := r.node(t, "a", 2, 3), r.node(t, "b", 3, 2)
	a.start(t)
	b.start(t)
	time.Sleep(600 * time.Millisecond)
	if _, ins := a.got(); len(kinds(ins, "peer-silent")) != 0 {
		t.Fatalf("silent while beating: %+v", ins)
	}
	b.stop()
	eventually(t, "peer-silent", 2*time.Second, func() bool { _, ins := a.got(); return len(kinds(ins, "peer-silent")) == 1 })
	_, ins := a.got()
	if in := kinds(ins, "peer-silent")[0]; !strings.Contains(in.Detail, "127.0.0.3") || !strings.Contains(in.Detail, "b") {
		t.Fatalf("%+v", in)
	}
	b = r.node(t, "b", 3, 2)
	b.start(t)
	eventually(t, "peer-back", 2*time.Second, func() bool { _, ins := a.got(); return len(kinds(ins, "peer-back")) == 1 })
	time.Sleep(200 * time.Millisecond)
	if _, ins := a.got(); len(kinds(ins, "peer-silent")) != 1 {
		t.Fatalf("%+v", ins)
	}
}

// A peer flooding hunts gets a bounded number taken and relayed, one
// alert for it, and cannot crowd out its own or others' beats.
func TestMesh_HuntFloodBounded(t *testing.T) {
	r := newRig(t, "a", "b")
	a := r.node(t, "a", 2, 3)
	a.start(t)
	url := "https://" + a.addr.String()
	_, bcli := r.tls(t, "b")
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: bcli}}
	post := func(path string, body []byte) int {
		resp, err := cl.Post(url+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	n := 0
	for range 3 {
		time.Sleep(time.Second) // a fresh rate window
		for range 20 {
			b, _ := json.Marshal(req(fmt.Sprintf("cmd %d", n)))
			n++
			post("/hunt", b)
		}
		if code := post("/beat", []byte(`{"host":"b"}`)); code != http.StatusOK {
			t.Fatalf("beat after hunts: %d", code)
		}
	}
	h, ins := a.got()
	if len(h) != PeerHunts || len(kinds(ins, "hunt-dropped")) != 1 {
		t.Fatalf("%d hunts, %d drop alerts", len(h), len(kinds(ins, "hunt-dropped")))
	}
}
