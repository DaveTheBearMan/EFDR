package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/sign"
)

const sshFrag = `"gray_users":["gray1"],"ssh":{"blue_users":["alice","bob"],"recovery":"xdrrecover","recovery_key":"ssh-ed25519 AAAA test","auto":["xdrops"],"grace":"15s"}`

func TestValidate_SSH(t *testing.T) {
	c, err := load(t, `{"jump":["192.0.2.7"],`+sshFrag+`}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSH == nil || c.SSH.Grace.Duration != 15*time.Second || c.SSH.Recovery != "xdrrecover" || len(c.SSH.Blue) != 2 || c.SSH.Auto[0] != "xdrops" {
		t.Fatalf("ssh: %+v", c.SSH)
	}
	c, err = load(t, `{"jump":["192.0.2.7"],"ssh":{"blue_users":["alice"]}}`)
	if err != nil || c.SSH.Grace.Duration != 90*time.Second {
		t.Fatalf("default grace: %+v %v", c, err)
	}
	if c, _ := load(t, `{"jump":["192.0.2.7"]}`); c.SSH != nil {
		t.Fatal("no ssh section should be nil")
	}
	for frag, want := range map[string]string{
		`"ssh":{"recovery":"xdrrecover"}`:                                      "ssh.recovery_key",
		`"gray_users":["gray1"],"ssh":{"blue_users":["gray1"]}`:                "ssh: gray1 is both",
		`"gray_users":["gray1"],"ssh":{"auto":["gray1"]}`:                      "ssh: gray1 is both",
		`"gray_users":["gray1"],"ssh":{"recovery":"gray1","recovery_key":"k"}`: "ssh: gray1 is both",
		`"ssh":{"grace":"5s"}`:                                                 "ssh.grace",
		`"ssh":{"blue_users":["Alice"]}`:                                       "ssh: bad user",
		`"ssh":{"auto":["a b"]}`:                                               "ssh: bad user",
		`"gray_users":["a,b"],"ssh":{"blue_users":["alice"]}`:                  "ssh: bad gray user",
		`"gray_users":["-x"],"ssh":{"blue_users":["alice"]}`:                   "ssh: bad gray user",
		`"gray_users":["a*"],"ssh":{"blue_users":["alice"]}`:                   "ssh: bad gray user",
	} {
		if _, err := load(t, `{"jump":["192.0.2.7"],`+frag+`}`); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", frag, err, want)
		}
	}
	// Gray accounts are the competition's, named as it likes; only what
	// sshd's and PAM's user lists cannot carry is refused.
	for _, g := range []string{"Gray.Team", "GRAY1", "svc$", "gray_2"} {
		if _, err := load(t, `{"jump":["192.0.2.7"],"gray_users":["`+g+`"],"ssh":{"blue_users":["alice"]}}`); err != nil {
			t.Errorf("gray %q: %v", g, err)
		}
	}
	// Empty jump is refused before the ssh section is looked at.
	if _, err := load(t, `{"jump":[],"ssh":{"blue_users":["alice"]}}`); err == nil || !strings.Contains(err.Error(), "jump") {
		t.Errorf("ssh without jump: %v", err)
	}
}

func writeSigned(t *testing.T, body string, key ed25519.PrivateKey) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+".sig", []byte(base64.StdEncoding.EncodeToString(sign.Sign("config", []byte(body), key))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSigned(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	body := `{"host":"web01","jump":["192.0.2.7"],` + sshFrag + `}`
	p := writeSigned(t, body, key)
	c, err := LoadSigned(p, pub)
	if err != nil || c.Host != "web01" || c.SSH == nil {
		t.Fatalf("signed config: %+v %v", c, err)
	}
	want := "config: unsigned or tampered (" + p + ".sig)"
	if err := os.WriteFile(p, []byte(strings.Replace(body, "web01", "web02", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigned(p, pub); err == nil || err.Error() != want {
		t.Errorf("tampered: %v", err)
	}
	p = writeSigned(t, body, other)
	if _, err := LoadSigned(p, pub); err == nil || !strings.Contains(err.Error(), "unsigned or tampered") {
		t.Errorf("other key: %v", err)
	}
	os.Remove(p + ".sig")
	if _, err := LoadSigned(p, pub); err == nil || !strings.Contains(err.Error(), "unsigned or tampered") {
		t.Errorf("no sig: %v", err)
	}
}
