// Package fleettest starts a controller's etcd for tests: a fresh
// controller directory, enrolled hosts, and a root client.
package fleettest

import (
	"net"
	"path/filepath"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/pki"
)

// Fleet is a running test etcd.
type Fleet struct {
	Dir    string // the controller directory
	Listen string // host:port of the client URL
	Etcd   *embed.Etcd
	Root   *clientv3.Client
	Start  func(t *testing.T) *Fleet // starts the same directory again
	bundle map[string]string
}

// Bundle is the enrolment bundle directory of host.
func (f *Fleet) Bundle(host string) string { return f.bundle[host] }

// FreePort is a localhost address nothing listens on right now.
func FreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// New initialises a controller directory with hosts enrolled and starts
// its etcd with start, which is controller.StartEtcd followed by
// controller.Bootstrap. It is passed in to keep this package below the
// controller.
func New(t *testing.T, start func(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client), hosts ...string) *Fleet {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ctl")
	if err := pki.Init(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	f := &Fleet{Dir: dir, Listen: FreePort(t), bundle: map[string]string{}}
	for _, h := range hosts {
		out := filepath.Join(t.TempDir(), h)
		if err := pki.Enroll(dir, h, out); err != nil {
			t.Fatal(err)
		}
		f.bundle[h] = out
	}
	f.Start = func(t *testing.T) *Fleet {
		t.Helper()
		f.Etcd, f.Root = start(t, f.Dir, f.Listen)
		return f
	}
	return f.Start(t)
}

// Enroll enrols one more host.
func (f *Fleet) Enroll(t *testing.T, host string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), host)
	if err := pki.Enroll(f.Dir, host, out); err != nil {
		t.Fatal(err)
	}
	f.bundle[host] = out
}

// Stop closes the root client and the etcd server.
func (f *Fleet) Stop() {
	f.Root.Close()
	f.Etcd.Close()
}
