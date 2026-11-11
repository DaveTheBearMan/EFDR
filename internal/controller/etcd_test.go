package controller

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/pki"
)

func start(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client) {
	t.Helper()
	e, c, err := StartEtcd(dir, listen)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := pki.Hosts(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Bootstrap(ctx, c, hosts); err != nil {
		c.Close()
		e.Close()
		t.Fatal(err)
	}
	return e, c
}

func newFleet(t *testing.T, hosts ...string) *fleettest.Fleet {
	t.Helper()
	f := fleettest.New(t, start, hosts...)
	t.Cleanup(f.Stop)
	return f
}

// hostClient connects as host, with its bundle.
func hostClient(t *testing.T, f *fleettest.Fleet, host string) *clientv3.Client {
	t.Helper()
	b := f.Bundle(host)
	tc, err := pki.ClientTLS(filepath.Join(b, "ca.pem"), filepath.Join(b, "host.pem"), filepath.Join(b, "host-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{f.Listen}, TLS: tc, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func ctx5(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func denied(err error) bool { return err != nil && strings.Contains(err.Error(), "permission denied") }

func TestEtcd_HostRBAC(t *testing.T) {
	f := newFleet(t, "web01", "db01")
	if _, err := f.Root.Put(ctx5(t), fleet.RulesKey, "x"); err != nil {
		t.Fatal(err)
	}
	c := hostClient(t, f, "web01")
	ctx := ctx5(t)
	if _, err := c.Put(ctx, fleet.Proposed("web01")+"x", "p"); err != nil {
		t.Fatalf("own proposal: %v", err)
	}
	if _, err := c.Put(ctx, fleet.Incidents("web01")+"1", "i"); err != nil {
		t.Fatalf("own incident: %v", err)
	}
	if _, err := c.Put(ctx, fleet.Hunt("web01")+"x", "h"); err != nil {
		t.Fatalf("own hunt: %v", err)
	}
	if r, err := c.Get(ctx, fleet.HuntAll, clientv3.WithPrefix()); err != nil || len(r.Kvs) != 1 {
		t.Fatalf("read hunts: %v", err)
	}
	for _, key := range []string{fleet.Proposed("db01") + "x", fleet.RulesKey, fleet.Heartbeat("db01"), fleet.Proposed("web01x") + "y", fleet.Hunt("db01") + "x", "/other"} {
		if _, err := c.Put(ctx, key, "x"); !denied(err) {
			t.Errorf("put %s: %v", key, err)
		}
	}
	if r, err := c.Get(ctx, fleet.RulesKey); err != nil || len(r.Kvs) != 1 {
		t.Fatalf("get rules: %v", err)
	}
	if _, err := c.Get(ctx, fleet.Proposed("db01"), clientv3.WithPrefix()); !denied(err) {
		t.Errorf("read another host's proposals: %v", err)
	}
	lease, err := c.Grant(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(ctx, fleet.Heartbeat("web01"), "{}", clientv3.WithLease(lease.ID)); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, err := c.Delete(ctx, fleet.Proposed("web01")+"x"); err != nil {
		t.Fatalf("delete own: %v", err)
	}
}

func TestEtcd_NoCertRefused(t *testing.T) {
	f := newFleet(t, "web01")
	b := f.Bundle("web01")
	tc, err := pki.ClientTLS(filepath.Join(b, "ca.pem"), filepath.Join(b, "host.pem"), filepath.Join(b, "host-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tc.Certificates = nil
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{f.Listen}, TLS: tc, DialTimeout: 2 * time.Second})
	if err == nil {
		defer c.Close()
		_, err = c.Get(ctx5(t), fleet.RulesKey)
	}
	if err == nil {
		t.Fatal("a client without a cert read the rules")
	}
}

func TestEtcd_BootstrapTwice(t *testing.T) {
	f := newFleet(t, "web01")
	f.Stop()
	f.Enroll(t, "db01")
	f.Start(t)
	c := hostClient(t, f, "db01")
	if _, err := c.Put(ctx5(t), fleet.Proposed("db01")+"x", "p"); err != nil {
		t.Fatalf("host enrolled after the first start: %v", err)
	}
	if _, err := hostClient(t, f, "web01").Put(ctx5(t), fleet.Proposed("web01")+"x", "p"); err != nil {
		t.Fatal(err)
	}
}

// History is compacted, or a stream of puts fills etcd's quota.
func TestEtcd_AutoCompaction(t *testing.T) {
	f := newFleet(t)
	c := f.Etcd.Config()
	if c.AutoCompactionMode != "periodic" || c.AutoCompactionRetention != "5m" {
		t.Fatalf("mode %q retention %q", c.AutoCompactionMode, c.AutoCompactionRetention)
	}
}

// The listener speaks TLS 1.3 only, as the clients do.
func TestEtcd_TLS13Only(t *testing.T) {
	f := newFleet(t, "web01")
	b := f.Bundle("web01")
	tc, err := pki.ClientTLS(filepath.Join(b, "ca.pem"), filepath.Join(b, "host.pem"), filepath.Join(b, "host-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	tc.MinVersion, tc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	conn, err := tls.Dial("tcp", f.Listen, tc)
	if err == nil {
		conn.Close()
		t.Fatal("a TLS 1.2 client got in")
	}
}
