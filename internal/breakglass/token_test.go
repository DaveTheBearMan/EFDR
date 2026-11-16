package breakglass

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func tok(action string) Token {
	return Token{V: 1, ID: "0123456789abcdef", Host: "web01", Action: action, NotBefore: now.Add(-time.Hour), Expires: now.Add(time.Hour)}
}

func TestToken_RoundTrip(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	s := Mint(tok("pause"), key)
	if strings.ContainsAny(s, " \n=+/") || strings.Count(s, ".") != 1 {
		t.Fatalf("wire form %q", s)
	}
	got, err := Parse(s, pub)
	if err != nil || got != tok("pause") {
		t.Fatalf("%+v %v", got, err)
	}
	if err := got.Valid("web01", now); err != nil {
		t.Fatal(err)
	}
}

func TestToken_Refusals(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	good := Mint(tok("approve-session"), key)
	payload, sig, _ := strings.Cut(good, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	raw[5] ^= 1
	flipped := base64.RawURLEncoding.EncodeToString(raw) + "." + sig
	for name, c := range map[string]struct {
		s    string
		host string
		at   time.Time
		want string
	}{
		"another host": {good, "web02", now, "another host"},
		"expired":      {good, "web01", now.Add(time.Hour + 6*time.Minute), "expired"},
		"not yet":      {good, "web01", now.Add(-time.Hour - 6*time.Minute), "not yet valid"},
		"another key":  {Mint(tok("pause"), other), "web01", now, "bad signature"},
		"flipped":      {flipped, "web01", now, "bad signature"},
		"no dot":       {payload, "web01", now, "malformed"},
		"garbage":      {"!!.!!", "web01", now, "malformed"},
		"bad action":   {Mint(Token{V: 1, ID: "0123456789abcdef", Host: "web01", Action: "root-shell", NotBefore: now, Expires: now.Add(time.Hour)}, key), "web01", now, "malformed"},
	} {
		got, err := Parse(c.s, pub)
		if err == nil {
			err = got.Valid(c.host, c.at)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestToken_Skew(t *testing.T) {
	if err := tok("pause").Valid("web01", now.Add(time.Hour+4*time.Minute)); err != nil {
		t.Fatalf("4 min past expiry: %v", err)
	}
	if err := tok("pause").Valid("web01", now.Add(-time.Hour-4*time.Minute)); err != nil {
		t.Fatalf("4 min early: %v", err)
	}
}

func TestGate_SpooledPauseToken(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	put := func(name, body string) { os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600) }
	put("a.tok", Mint(tok("approve-session"), key)+"\n7\n")
	other := tok("pause")
	other.Host = "web02"
	put("b.tok", Mint(other, key)+"\n")
	if Paused(dir, pub, "web01", now) {
		t.Fatal("paused by an approve token or another host's")
	}
	put("c.tok", Mint(tok("pause"), key)+"\n")
	if !Paused(dir, pub, "web01", now) {
		t.Fatal("this host's pause token ignored")
	}
	if Paused(dir, pub, "web01", now.Add(2*time.Hour)) {
		t.Fatal("expired pause holds")
	}
}
