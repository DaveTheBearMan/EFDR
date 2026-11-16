package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/creds"
)

func rotateDir(t *testing.T) string {
	dir, _ := fleetConfig(t)
	os.WriteFile(filepath.Join(dir, "controller.json"), []byte(`{"listen":"127.0.0.1:1","gray_users":["gray1"],"recovery":"xdrrecover","auto":["xdrops"]}`), 0o600)
	return dir
}

func TestRotate_RefusesGray(t *testing.T) {
	dir := rotateDir(t)
	for _, u := range []string{"gray1", "xdrrecover", "xdrops"} {
		var so, se bytes.Buffer
		if code := Run([]string{"controller", "rotate", "--dir", dir, "--host", "web01", "--users", "alice," + u}, &so, &se); code == 0 || !strings.Contains(se.String(), "refused: "+u) {
			t.Errorf("%s: exit %d %q", u, code, se.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "creds.json")); err == nil {
		t.Fatal("store written for a refused rotation")
	}
}

func TestRotate_StoreBeforePut(t *testing.T) {
	dir := rotateDir(t)
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "rotate", "--dir", dir, "--host", "web01", "--users", "alice", "--samba", "alice"}, &so, &se); code == 0 {
		t.Fatal("etcd down, yet rotate succeeded")
	}
	s, err := creds.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := s.Hosts["web01"]["alice"]
	if len(e.Password) != 20 || e.Service != "samba" {
		t.Fatalf("store %+v", s.Hosts)
	}
	so.Reset()
	if code := Run([]string{"controller", "creds", "--dir", dir, "--host", "web01"}, &so, &se); code != 0 || so.String() != "web01\tsamba\talice\t"+e.Password+"\n" {
		t.Fatalf("creds: %d %q", code, so.String())
	}
}
