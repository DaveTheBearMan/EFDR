package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"xdr/internal/creds"
	"xdr/internal/fleet"
	"xdr/internal/testfs"
)

type stdinCall struct {
	stdin string
	cmd   []string
}

func credsRig(t *testing.T) (*rig, *[][]string, *[]stdinCall) {
	r, ran := usersRig(t)
	var ins []stdinCall
	r.a.runIn = func(stdin []byte, name string, args ...string) error {
		ins = append(ins, stdinCall{string(stdin), append([]string{name}, args...)})
		return nil
	}
	return r, ran, &ins
}

func credsOrder(s creds.Set) fleet.Order {
	b, _ := json.Marshal(s)
	return fleet.Order{Kind: "creds", Value: b}
}

const aliceHash = "$6$abcdefgh$xyz"

func TestApplyCreds_Chpasswd(t *testing.T) {
	r, _, ins := credsRig(t)
	r.a.onOrder(credsOrder(creds.Set{ID: "s1", Users: map[string]creds.User{"alice": {Hash: aliceHash}}}))
	if len(*ins) != 1 || (*ins)[0].stdin != "alice:"+aliceHash+"\n" || !slices.Equal((*ins)[0].cmd, []string{"chpasswd", "-e"}) {
		t.Fatalf("%+v", *ins)
	}
	if got := r.kind("creds-applied"); len(got) != 1 || !strings.Contains(got[0].Detail, "alice") {
		t.Fatalf("%+v", got)
	}
}

func TestApplyCreds_GrayRefusedAgentSide(t *testing.T) {
	r, _, ins := credsRig(t)
	r.a.onOrder(credsOrder(creds.Set{ID: "s2", Users: map[string]creds.User{"gray1": {Hash: aliceHash}, "svc": {Hash: aliceHash}, "alice": {Hash: aliceHash}}}))
	if len(*ins) != 1 || (*ins)[0].stdin != "alice:"+aliceHash+"\n" {
		t.Fatalf("%+v", *ins)
	}
	refused := map[string]bool{}
	for _, in := range r.kind("creds-refused") {
		refused[in.User] = true
	}
	if !refused["gray1"] || !refused["svc"] {
		t.Fatalf("refused %v", refused)
	}
}

func TestApplyCreds_Idempotent(t *testing.T) {
	r, _, ins := credsRig(t)
	s := creds.Set{ID: "s3", Users: map[string]creds.User{"alice": {Hash: aliceHash}}}
	r.a.onOrder(credsOrder(s))
	r.a.onOrder(credsOrder(s))
	if len(*ins) != 1 {
		t.Fatalf("applied %d times", len(*ins))
	}
	if b, _ := os.ReadFile(filepath.Join(r.a.state, "creds-applied")); strings.TrimSpace(string(b)) != "s3" {
		t.Fatalf("applied id %q", b)
	}
}

func TestApplyCreds_SambaNT(t *testing.T) {
	r, ran, _ := credsRig(t)
	r.a.onOrder(credsOrder(creds.Set{ID: "s4", Users: map[string]creds.User{"svc": {Hash: aliceHash, NT: "8846f7eaee8fb117ad06bdd830b7586c"}}}))
	if !slices.ContainsFunc(*ran, func(c []string) bool {
		return slices.Equal(c, []string{"pdbedit", "-u", "svc", "--set-nt-hash", "8846f7eaee8fb117ad06bdd830b7586c"})
	}) {
		t.Fatalf("ran %v", *ran)
	}
}

func TestApplyCreds_Keys(t *testing.T) {
	r, _, _ := credsRig(t)
	r.a.onOrder(credsOrder(creds.Set{ID: "s5", Users: map[string]creds.User{"alice": {Hash: aliceHash, Keys: []string{"ssh-ed25519 AAAA new"}}}}))
	if b, _ := os.ReadFile(filepath.Join(r.root, "home/alice/.ssh/authorized_keys")); string(b) != "ssh-ed25519 AAAA new\n" {
		t.Fatalf("keys %q", b)
	}
}

func TestApplyCreds_HostKeys(t *testing.T) {
	r, ran, _ := credsRig(t)
	testfs.File(t, r.root, "etc/ssh/ssh_host_ed25519_key", "old", 0o600)
	testfs.File(t, r.root, "etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOld old", 0o644)
	r.a.run = func(name string, args ...string) error {
		*ran = append(*ran, append([]string{name}, args...))
		if name == "ssh-keygen" {
			testfs.File(t, r.root, "etc/ssh/ssh_host_ed25519_key", "new", 0o600)
			testfs.File(t, r.root, "etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINew root@x", 0o644)
		}
		return nil
	}
	r.a.onOrder(credsOrder(creds.Set{ID: "s6", Users: map[string]creds.User{}, HostKeys: true}))
	if b, _ := os.ReadFile(filepath.Join(r.root, "etc/ssh/ssh_host_ed25519_key")); string(b) != "new" {
		t.Fatalf("key %q", b)
	}
	got := r.kind("creds-applied")
	if len(got) != 1 || !strings.Contains(got[0].Detail, "SHA256:") {
		t.Fatalf("%+v", got)
	}
	var gen, reload bool
	for _, c := range *ran {
		gen = gen || slices.Equal(c, []string{"ssh-keygen", "-A", "-f", r.root})
		reload = reload || c[0] == "systemctl"
	}
	if !gen || !reload {
		t.Fatalf("ran %v", *ran)
	}
}

func TestApplyCreds_NoHashInIncident(t *testing.T) {
	r, _, _ := credsRig(t)
	r.a.onOrder(credsOrder(creds.Set{ID: "s7", Users: map[string]creds.User{"alice": {Hash: aliceHash}, "gray1": {Hash: aliceHash, NT: "8846f7eaee8fb117ad06bdd830b7586c"}}}))
	for _, in := range r.got {
		b, _ := json.Marshal(in)
		if strings.Contains(string(b), "$6$") || strings.Contains(string(b), "8846f7ea") {
			t.Fatalf("hash in incident: %s", b)
		}
	}
}
