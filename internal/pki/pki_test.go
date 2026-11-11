package pki

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func initDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ctl")
	if err := Init(dir, []string{"127.0.0.1", "jump.example"}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestInit_Files(t *testing.T) {
	dir := initDir(t)
	for name, mode := range map[string]os.FileMode{
		"ca.pem": 0o644, "ca-key.pem": 0o600, "server.pem": 0o644, "server-key.pem": 0o600,
		"root.pem": 0o644, "root-key.pem": 0o600, "rules.pub": 0o644, "rules.key": 0o600,
	} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want %v", name, st.Mode(), err, mode)
		}
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir %v", st.Mode())
	}
	if err := Init(dir, []string{"127.0.0.1"}); err == nil {
		t.Fatal("second init succeeded")
	}
}

// handshake runs one TLS handshake and returns the client cert's CN as the
// server saw it.
func handshake(t *testing.T, srv, cli *tls.Config) (string, error) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cn := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			cn <- ""
			return
		}
		defer c.Close()
		tc := c.(*tls.Conn)
		if tc.Handshake() != nil || len(tc.ConnectionState().PeerCertificates) == 0 {
			cn <- ""
			return
		}
		cn <- tc.ConnectionState().PeerCertificates[0].Subject.CommonName
		io.WriteString(c, "x")
	}()
	cli = cli.Clone()
	cli.ServerName = "127.0.0.1"
	c, err := tls.Dial("tcp", ln.Addr().String(), cli)
	if err == nil {
		_, err = c.Read(make([]byte, 1))
		c.Close()
	}
	return <-cn, err
}

func TestEnroll_HandshakeAndCN(t *testing.T) {
	dir := initDir(t)
	out := filepath.Join(t.TempDir(), "web01")
	if err := Enroll(dir, "web01", out); err != nil {
		t.Fatal(err)
	}
	srv, err := serverTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ClientTLS(filepath.Join(out, "ca.pem"), filepath.Join(out, "host.pem"), filepath.Join(out, "host-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if cn, err := handshake(t, srv, cli); err != nil || cn != "web01" {
		t.Fatalf("cn %q, %v", cn, err)
	}

	other := initDir(t)
	otherOut := filepath.Join(t.TempDir(), "web01")
	if err := Enroll(other, "web01", otherOut); err != nil {
		t.Fatal(err)
	}
	stranger, err := ClientTLS(filepath.Join(out, "ca.pem"), filepath.Join(otherOut, "host.pem"), filepath.Join(otherOut, "host-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if cn, err := handshake(t, srv, stranger); err == nil || cn != "" {
		t.Fatalf("a cert from another CA got in: %q", cn)
	}
}

func TestEnroll_NoSecretsInBundle(t *testing.T) {
	dir := initDir(t)
	out := filepath.Join(t.TempDir(), "b")
	if err := Enroll(dir, "web01", out); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(out)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"ca.pem", "host-key.pem", "host.pem", "rules.pub"}) {
		t.Fatalf("bundle %v", names)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o700 {
		t.Errorf("bundle dir %v", st.Mode())
	}
}

func TestEnroll_HostsList(t *testing.T) {
	dir := initDir(t)
	for _, h := range []string{"web01", "db01", "web01"} {
		if err := Enroll(dir, h, filepath.Join(t.TempDir(), h)); err != nil {
			t.Fatal(err)
		}
	}
	if hs, err := Hosts(dir); err != nil || !slices.Equal(hs, []string{"web01", "db01"}) {
		t.Fatalf("%v %v", hs, err)
	}
}

func TestEnroll_BadHost(t *testing.T) {
	dir := initDir(t)
	for _, h := range []string{"../x", "root", ""} {
		if err := Enroll(dir, h, filepath.Join(t.TempDir(), "x")); err == nil {
			t.Errorf("%q enrolled", h)
		}
	}
}

// serverTLS is a listener as etcd's is set up: the server cert, client
// certs from the CA required.
func serverTLS(dir string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"))
	if err != nil {
		return nil, err
	}
	p, err := pool(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		ClientCAs:    p,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
