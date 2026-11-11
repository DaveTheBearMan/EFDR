package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const sum = "ab12000000000000000000000000000000000000000000000000000000000000"

func hashRule() Rule {
	r := Rule{Kind: "hash", SHA256: sum, Exe: "/tmp/.x", From: "web01", Seen: t0, Detail: "egress"}
	r.SetID()
	return r
}

func remoteRule() Rule {
	r := Rule{Kind: "remote", Addr: netip.MustParseAddr("203.0.113.9"), Port: 4444, Proto: "tcp", From: "db01", Seen: t0}
	r.SetID()
	return r
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSign_RoundTrip(t *testing.T) {
	pub, priv := keys(t)
	s := &Set{Version: 7, Issued: t0, Rules: []Rule{hashRule(), remoteRule()}}
	e, err := Sign(s, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Unmarshal(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(e2, pub)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("got  %+v\nwant %+v", got, s)
	}
	ix := got.Lookup()
	if ix.Hash[sum] == nil || ix.Remote[RemoteKey{netip.MustParseAddr("203.0.113.9"), 4444, "tcp"}] == nil {
		t.Fatalf("index %+v", ix)
	}
}

func TestOpen_Tampered(t *testing.T) {
	pub, priv := keys(t)
	other, _ := keys(t)
	e, err := Sign(&Set{Version: 1, Rules: []Rule{hashRule()}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	bad := Envelope{Payload: append([]byte(nil), e.Payload...), Sig: e.Sig}
	bad.Payload[len(bad.Payload)/2] ^= 1
	if _, err := Open(bad, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered payload: %v", err)
	}
	if _, err := Open(e, other); !errors.Is(err, ErrBadSignature) {
		t.Errorf("other key: %v", err)
	}
}

func TestOpen_IDMismatch(t *testing.T) {
	pub, priv := keys(t)
	r := hashRule()
	r.ID = "0000000000000000"
	e, err := Sign(&Set{Version: 1, Rules: []Rule{r}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(e, pub); err == nil || !strings.Contains(err.Error(), "id") {
		t.Fatalf("got %v", err)
	}
}

func TestRule_Key(t *testing.T) {
	h, r := hashRule(), remoteRule()
	if h.Key() == r.Key() || h.ID == r.ID || len(h.ID) != 16 {
		t.Fatalf("%q %q %q %q", h.Key(), r.Key(), h.ID, r.ID)
	}
	for _, c := range []struct {
		r    Rule
		want string
	}{
		{Rule{Kind: "parent", ParentExe: "/usr/sbin/apache2", Exe: "/usr/bin/dash"}, "parent:/usr/sbin/apache2>/usr/bin/dash"},
		{Rule{Kind: "unit", Unit: "evil.service", SHA256: sum}, "unit:evil.service@" + sum},
		{Rule{Kind: "cron", Command: "curl x | sh"}, "cron:curl x | sh"},
	} {
		if got := c.r.Key(); got != c.want {
			t.Errorf("key %q, want %q", got, c.want)
		}
	}
	m := r
	m.Addr = netip.MustParseAddr("::ffff:203.0.113.9")
	m.SetID()
	if m.ID != r.ID || m.Addr != r.Addr {
		t.Fatalf("mapped %q %v, plain %q %v", m.ID, m.Addr, r.ID, r.Addr)
	}
}

func TestLoadPrivate_Mode(t *testing.T) {
	_, priv := keys(t)
	path := filepath.Join(t.TempDir(), "rules.key")
	if err := WritePrivate(path, priv); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(path); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadPrivate(path); err == nil || !strings.Contains(err.Error(), "644") {
		t.Fatalf("got %v", err)
	}
	pubPath := filepath.Join(t.TempDir(), "rules.pub")
	if err := WritePublic(pubPath, priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if pub, err := LoadPublic(pubPath); err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("%v %v", pub, err)
	}
}

func TestLookup_NewKinds(t *testing.T) {
	s := &Set{Rules: []Rule{
		{Kind: "parent", ParentExe: "/usr/sbin/apache2", Exe: "/usr/bin/dash"},
		{Kind: "unit", Unit: "evil.service", SHA256: sum},
		{Kind: "cron", Command: "curl x | sh"},
	}}
	ix := s.Lookup()
	if ix.Parent[ParentKey{"/usr/sbin/apache2", "/usr/bin/dash"}] == nil || ix.Unit[UnitKey{"evil.service", sum}] == nil ||
		ix.Cron["curl x | sh"] == nil || len(ix.Hash) != 0 {
		t.Fatalf("%+v", ix)
	}
}
