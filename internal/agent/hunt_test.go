package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xdr/internal/config"
	"xdr/internal/detect"
	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/sensor"
)

type fakeMesh struct {
	mu     sync.Mutex
	hunts  []*hunt.Request
	pushes int
}

func (m *fakeMesh) PushHunt(r *hunt.Request, _ netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hunts = append(m.hunts, r)
}

func (m *fakeMesh) PushRules() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pushes++
}

func sumOf(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

// huntRig is a fleet rig with a mesh and a running hunt runner. Its
// incidents are read under the agent's lock.
func huntRig(t *testing.T) (*rig, *fakeFleet, *fakeMesh) {
	r, f := fleetRig(t)
	m := &fakeMesh{}
	r.a.mesh = m
	ctx, cancel := context.WithCancel(context.Background())
	stop := r.a.startHunts(ctx)
	t.Cleanup(func() { cancel(); stop() })
	return r, f, m
}

func (r *rig) kindLocked(kind string) []incident.Incident {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	return r.kind(kind)
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within 3s: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func fileHunt(from string, f hunt.File) *hunt.Request {
	ioc := hunt.IOC{Files: []hunt.File{f}}
	return &hunt.Request{ID: hunt.ID(ioc), From: from, IOC: ioc}
}

func TestHunt_StartedFromKill(t *testing.T) {
	r, f, m := huntRig(t)
	x := mk(300, 100, 1000, "/tmp/.x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(f.hunts) != 1 || len(m.hunts) != 1 || f.hunts[0] != m.hunts[0] {
		t.Fatalf("put %d, pushed %d", len(f.hunts), len(m.hunts))
	}
	h := f.hunts[0]
	if h.From != "web01" || len(h.IOC.Files) != 1 || h.IOC.Files[0].SHA256 != hexSum("/tmp/.x") || h.IOC.Files[0].Path != "/tmp/.x" || len(h.IOC.Remotes) != 1 {
		t.Fatalf("%+v", h)
	}
	// It comes back over etcd: not searched here.
	searched := atomic.Int32{}
	r.a.search = func(context.Context, *hunt.Request) hunt.Result { searched.Add(1); return hunt.Result{} }
	r.a.offerHunt(h, "etcd")
	time.Sleep(50 * time.Millisecond)
	if searched.Load() != 0 {
		t.Fatal("own hunt searched")
	}
}

// Gray-team and system accounts are never user indicators: every box
// has them, so every box would report a hit.
func TestHunt_GrayAndSystemUsersNotHunted(t *testing.T) {
	r, f, _ := huntRig(t)
	r.a.users[110] = "mysql"
	for i, uid := range []uint32{2001, 110} {
		x := mk(300+i, 100, uid, "/tmp/.x")
		d := egress(x)
		d.Kind = "revshell-stdio" // killed even for a gray account
		r.a.handle(tree(x), []detect.Detection{d})
	}
	if len(f.hunts) != 2 {
		t.Fatalf("%d hunts", len(f.hunts))
	}
	for _, h := range f.hunts {
		if len(h.IOC.Users) != 0 {
			t.Fatalf("users %v", h.IOC.Users)
		}
	}
}

func TestHunt_Search(t *testing.T) {
	r, _, _ := huntRig(t)
	body := "implant"
	if err := os.MkdirAll(filepath.Join(r.root, "var/tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, "var/tmp/.cache-helper"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	r.snap = tree()
	r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf(body), Size: int64(len(body))}), "etcd")
	waitFor(t, "hunt-hit", func() bool { return len(r.kindLocked("hunt-hit")) == 1 })
	in := r.kindLocked("hunt-hit")[0]
	if !strings.Contains(in.Detail, "/var/tmp/.cache-helper") || !strings.HasPrefix(in.Detail, "hunt ") || in.Hunt == "" || in.Severity.String() != "high" {
		t.Fatalf("%+v", in)
	}
	r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf("absent"), Size: 6}), "etcd")
	waitFor(t, "hunt-clean", func() bool { return len(r.kindLocked("hunt-clean")) == 1 })
}

func TestHunt_VariantProposed(t *testing.T) {
	r, f, _ := huntRig(t)
	if err := os.MkdirAll(filepath.Join(r.root, "var/tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, "var/tmp/v"), []byte("variant"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.snap = tree()
	r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf("original"), Size: 8, Path: "/var/tmp/v"}), "etcd")
	waitFor(t, "hunt-hit", func() bool { return len(r.kindLocked("hunt-hit")) == 1 })
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if len(f.proposed) != 1 || f.proposed[0].Kind != "hash" || f.proposed[0].SHA256 != sumOf("variant") || f.proposed[0].Exe != "/var/tmp/v" {
		t.Fatalf("%+v", f.proposed)
	}
}

// A new hash at a hunted path outside the drop directories is reported,
// not proposed: a peer could name a real service binary to have it ruled.
func TestHunt_VariantOutsideDropDirsNotProposed(t *testing.T) {
	r, f, _ := huntRig(t)
	if err := os.MkdirAll(filepath.Join(r.root, "usr/lib/postfix/sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, "usr/lib/postfix/sbin/qmgr"), []byte("genuine"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.snap = tree()
	r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf("original"), Size: 8, Path: "/usr/lib/postfix/sbin/qmgr"}), "peer 192.0.2.4")
	waitFor(t, "hunt-hit", func() bool { return len(r.kindLocked("hunt-hit")) == 1 })
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if len(f.proposed) != 0 {
		t.Fatalf("%+v", f.proposed)
	}
}

func TestHunt_Dedup(t *testing.T) {
	r, _, _ := huntRig(t)
	n := atomic.Int32{}
	r.a.search = func(context.Context, *hunt.Request) hunt.Result { n.Add(1); return hunt.Result{} }
	h := fileHunt("db01", hunt.File{SHA256: sumOf("x"), Size: 1})
	r.a.offerHunt(h, "etcd")
	r.a.offerHunt(h, "peer 192.0.2.4")
	waitFor(t, "searched", func() bool { return n.Load() == 1 })
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("%d searches", n.Load())
	}
}

func TestHunt_PerSenderCap(t *testing.T) {
	r, _, _ := huntRig(t)
	n := atomic.Int32{}
	r.a.search = func(context.Context, *hunt.Request) hunt.Result { n.Add(1); return hunt.Result{} }
	for i := range 31 {
		r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf("x"), Size: int64(i)}), "etcd")
		if i < 30 {
			waitFor(t, "searched", func() bool { return n.Load() == int32(i+1) })
		}
	}
	waitFor(t, "hunt-dropped", func() bool { return len(r.kindLocked("hunt-dropped")) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 30 {
		t.Fatalf("%d searches", n.Load())
	}
}

// Over the mesh, the cap is on the peer that relayed the hunt: a peer
// cannot dodge it by naming a new sender each time.
func TestHunt_PerRelayCap(t *testing.T) {
	r, _, _ := huntRig(t)
	n := atomic.Int32{}
	r.a.search = func(context.Context, *hunt.Request) hunt.Result { n.Add(1); return hunt.Result{} }
	for i := range 31 {
		r.a.offerHunt(fileHunt(fmt.Sprintf("h%02d", i), hunt.File{SHA256: sumOf("x"), Size: int64(i)}), "peer 192.0.2.4")
		if i < 30 {
			waitFor(t, "searched", func() bool { return n.Load() == int32(i+1) })
		}
	}
	waitFor(t, "hunt-dropped", func() bool { return len(r.kindLocked("hunt-dropped")) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 30 {
		t.Fatalf("%d searches", n.Load())
	}
}

// A full queue is reported once per window, not once per hunt.
func TestHunt_QueueFullToldOnce(t *testing.T) {
	r, _, _ := huntRig(t)
	block, started := make(chan struct{}), make(chan struct{}, 1)
	r.a.search = func(context.Context, *hunt.Request) hunt.Result {
		started <- struct{}{}
		<-block
		return hunt.Result{}
	}
	defer close(block)
	r.a.offerHunt(fileHunt("h00", hunt.File{SHA256: sumOf("x"), Size: 0}), "etcd")
	<-started
	for i := 1; i <= huntQueue+5; i++ {
		r.a.offerHunt(fileHunt(fmt.Sprintf("h%02d", i), hunt.File{SHA256: sumOf("x"), Size: int64(i)}), "etcd")
	}
	if d := r.kindLocked("hunt-dropped"); len(d) != 1 {
		t.Fatalf("%d drop alerts", len(d))
	}
}

func TestHunt_DoesNotBlockEvents(t *testing.T) {
	r, _, _ := huntRig(t)
	block, started := make(chan struct{}), make(chan struct{})
	r.a.search = func(context.Context, *hunt.Request) hunt.Result {
		close(started)
		<-block
		return hunt.Result{}
	}
	defer close(block)
	r.a.offerHunt(fileHunt("db01", hunt.File{SHA256: sumOf("x"), Size: 1}), "etcd")
	<-started
	x := mk(300, 100, 1000, "/tmp/x")
	r.snap = tree(x)
	r.a.onEvents([]sensor.Event{{Kind: sensor.Connect, PID: 300, Dst: netip.MustParseAddrPort("203.0.113.9:4444"), Proto: "tcp"}})
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if len(r.kills) != 1 || r.kills[0].pid != 300 {
		t.Fatalf("kills %+v", r.kills)
	}
}

func TestMeshAddrs(t *testing.T) {
	peers := []config.Net{pfx("192.0.2.4/32"), pfx("192.0.2.5/32"), pfx("192.0.2.6/32")}
	local := func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.5") }
	listen, out := meshAddrs(peers, 7443, local)
	if listen.String() != "192.0.2.5:7443" || len(out) != 2 || out[0].String() != "192.0.2.4:7443" || out[1].String() != "192.0.2.6:7443" {
		t.Fatalf("%v %v", listen, out)
	}
	listen, out = meshAddrs(peers, 7443, func(netip.Addr) bool { return false })
	if listen.String() != "[::]:7443" || len(out) != 3 {
		t.Fatalf("%v %v", listen, out)
	}
}
