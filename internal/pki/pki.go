// Package pki makes the jump box's certificate authority, the controller's
// server and client certs, the rule-signing key, and one client cert per
// enrolled host.
package pki

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"xdr/internal/config"
	"xdr/internal/rules"
)

const validity = 5 * 365 * 24 * time.Hour

func write(path string, typ string, der []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue writes a cert signed by c (or self-signed when c is nil) and its
// key, as name.pem and name-key.pem in dir.
func issue(dir, name string, tmpl *x509.Certificate, c *ca) (*ca, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if tmpl.SerialNumber, err = serial(); err != nil {
		return nil, err
	}
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = tmpl.NotBefore.Add(validity)
	parent, signer := tmpl, key
	if c != nil {
		parent, signer = c.cert, c.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := write(filepath.Join(dir, name+"-key.pem"), "EC PRIVATE KEY", kder, 0o600); err != nil {
		return nil, err
	}
	if err := write(filepath.Join(dir, name+".pem"), "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &ca{cert, key}, err
}

func client(cn string) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

// Init makes a new controller directory: the CA, a server cert for
// serverNames (addresses or DNS names), the controller's own client cert
// (CN root) and the rule-signing key.
func Init(dir string, serverNames []string) error {
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); err == nil {
		return fmt.Errorf("%s: already initialised", dir)
	}
	if len(serverNames) == 0 {
		return errors.New("no server name")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	root, err := issue(dir, "ca", &x509.Certificate{
		Subject:               pkix.Name{CommonName: "xdr fleet CA"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil)
	if err != nil {
		return err
	}
	srv := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "xdr controller"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range serverNames {
		if ip := net.ParseIP(n); ip != nil {
			srv.IPAddresses = append(srv.IPAddresses, ip)
		} else {
			srv.DNSNames = append(srv.DNSNames, n)
		}
	}
	if _, err := issue(dir, "server", srv, root); err != nil {
		return err
	}
	if _, err := issue(dir, "root", client("root"), root); err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := rules.WritePrivate(filepath.Join(dir, "rules.key"), key); err != nil {
		return err
	}
	return rules.WritePublic(filepath.Join(dir, "rules.pub"), pub)
}

func loadCA(dir string) (*ca, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("ca key is not ECDSA")
	}
	return &ca{cert, key}, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Enroll makes host's bundle in out: the CA cert, a client cert with CN
// host and its key, and the rule-signing public key. It records host in
// the controller's hosts file.
func Enroll(dir, host, out string) error {
	if !config.Hostname(host) || host == "root" {
		return fmt.Errorf("bad host name %q", host)
	}
	c, err := loadCA(dir)
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		return err
	}
	if _, err := issue(out, "host", client(host), c); err != nil {
		return err
	}
	for _, name := range []string{"ca.pem", "rules.pub"} {
		if err := copyFile(filepath.Join(dir, name), filepath.Join(out, name), 0o644); err != nil {
			return err
		}
	}
	hosts, err := Hosts(dir)
	if err != nil || slices.Contains(hosts, host) {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "hosts"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, host); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Hosts lists the enrolled hosts in the order they were enrolled.
func Hosts(dir string) ([]string, error) {
	f, err := os.Open(filepath.Join(dir, "hosts"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if h := strings.TrimSpace(sc.Text()); h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out, sc.Err()
}

func pool(caPath string) (*x509.CertPool, error) {
	b, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificate", caPath)
	}
	return p, nil
}

// ServerTLS is the controller's listener config: its server cert, and
// client certs from the CA required.
func ServerTLS(dir string) (*tls.Config, error) {
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

// ClientTLS is a client config presenting cert and trusting only the CA.
func ClientTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	p, err := pool(caPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: p, MinVersion: tls.VersionTLS13}, nil
}
