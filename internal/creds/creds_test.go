package creds

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSHA512Crypt_Vectors(t *testing.T) {
	for _, v := range []struct {
		pw, salt string
		rounds   int
		want     string
	}{
		{"Hello world!", "saltstring", 5000, "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"Hello world!", "saltstringsaltstring", 10000, "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
		{"a much longer password that goes past sixty-four bytes in length, yes indeed", "abc", 5000, "$6$abc$qyFhCSlMZMtJMurEZ.xWwuoHum2mwuECNWsOhLbauc.r4Ag0vyVeqO361Wp8RoE74s6QgV3Cf2c5y1s1ptn3F0"},
		{"", "x", 5000, "$6$x$QSmr1Bx2g4O6BzKvdkgOcyU6H91X6I/XBv5pSalMhSPkwdH6Beo3F455xZJg0v//bxVK5F4OE5k1.0xuR26MK0"},
	} {
		if got := SHA512Crypt(v.pw, v.salt, v.rounds); got != v.want {
			t.Errorf("%q %q %d:\n got %s\nwant %s", v.pw, v.salt, v.rounds, got, v.want)
		}
	}
}

func TestNTHash(t *testing.T) {
	if got := NTHash("password"); got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatal(got)
	}
}

func TestPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		p := Password()
		if !regexp.MustCompile(`^[A-Za-z0-9]{20}$`).MatchString(p) || seen[p] {
			t.Fatalf("%q", p)
		}
		seen[p] = true
	}
	if h := Hash("x"); !strings.HasPrefix(h, "$6$") || len(strings.Split(h, "$")[2]) != 16 {
		t.Fatalf("hash %s", h)
	}
}

func TestStore_BlockAndMode(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	s.Put("web01", "bob", Entry{Password: "p2", Service: "ssh", Rotated: at})
	s.Put("db01", "alice", Entry{Password: "p1", Service: "samba", Rotated: at})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "creds.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	s2, _ := Load(dir)
	if got := s2.Block(""); got != "db01\tsamba\talice\tp1\nweb01\tssh\tbob\tp2\n" {
		t.Fatalf("%q", got)
	}
	if got := s2.Block("web01"); got != "web01\tssh\tbob\tp2\n" {
		t.Fatalf("%q", got)
	}
}

func TestSet_HoldsNoCleartext(t *testing.T) {
	pw := map[string]string{"alice": Password(), "bob": Password()}
	set := NewSet(pw, []string{"bob"}, nil, false)
	b, _ := json.Marshal(set)
	for _, p := range pw {
		if strings.Contains(string(b), p) {
			t.Fatal("cleartext in the set")
		}
	}
	if set.Users["bob"].NT != NTHash(pw["bob"]) || set.Users["alice"].NT != "" || !strings.HasPrefix(set.Users["alice"].Hash, "$6$") || set.ID == "" {
		t.Fatalf("%+v", set)
	}
}
