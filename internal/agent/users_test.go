package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"xdr/internal/model"
	"xdr/internal/testfs"
)

const passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n" +
	"evil:x:1500:1500::/home/evil:/bin/bash\nmysql:x:110:110::/nonexistent:/bin/false\n" +
	"svc:x:1600:1600::/home/svc:/bin/bash\ngray1:x:2001:2001::/home/gray1:/bin/bash\n" +
	"xdrrecover:x:1900:1900::/home/xdrrecover:/bin/bash\n"

func usersRig(t *testing.T) (*rig, *[][]string) {
	r, ran := gateOn(t)
	r.a.state = t.TempDir()
	testfs.File(t, r.root, "etc/passwd", passwd, 0o644)
	testfs.File(t, r.root, "home/xdrrecover/.ssh/authorized_keys", "ssh-ed25519 AAAA k\n", 0o600)
	r.snap = tree(mk(700, 1, 1600, "/usr/sbin/apache2"))
	return r, ran
}

func usermods(ran [][]string) [][]string {
	var out [][]string
	for _, c := range ran {
		if c[0] == "usermod" {
			out = append(out, c)
		}
	}
	return out
}

func TestUsers_NewLoginUserDisabled(t *testing.T) {
	r, ran := usersRig(t)
	r.a.accounts(r.snap)
	r.a.accounts(r.snap)
	um := usermods(*ran)
	if len(um) != 1 || !slices.Equal(um[0], []string{"usermod", "--lock", "--expiredate", "1", "evil"}) {
		t.Fatalf("usermod %v", um)
	}
	if got := r.kind("user-disabled"); len(got) != 1 || got[0].User != "evil" || got[0].Severity != model.SevHigh {
		t.Fatalf("user-disabled %+v", got)
	}
}

func TestUsers_SystemAndServiceAccountsNotDisabled(t *testing.T) {
	r, ran := usersRig(t)
	r.a.accounts(r.snap)
	for _, c := range usermods(*ran) {
		if c[len(c)-1] != "evil" {
			t.Errorf("touched %v", c)
		}
	}
	news := map[string]bool{}
	for _, in := range r.kind("user-new") {
		news[in.User] = true
	}
	if !news["mysql"] || !news["svc"] || news["gray1"] || news["xdrrecover"] || news["alice"] {
		t.Fatalf("user-new %v", news)
	}
	r.a.accounts(r.snap)
	if len(r.kind("user-new")) != 2 {
		t.Fatal("alerted twice")
	}
}

func TestUsers_ApprovedReenabled(t *testing.T) {
	r, ran := usersRig(t)
	r.a.accounts(r.snap)
	r.a.onOrder(order("user", "evil", "approve"))
	r.a.accounts(r.snap)
	um := usermods(*ran)
	if len(um) != 2 || !slices.Equal(um[1], []string{"usermod", "--unlock", "--expiredate", "", "evil"}) {
		t.Fatalf("usermod %v", um)
	}
	if len(r.kind("user-enabled")) != 1 {
		t.Fatal("no user-enabled")
	}
	r.a.accounts(r.snap)
	if len(usermods(*ran)) != 2 {
		t.Fatal("unlocked again")
	}
}

func TestRecovery_KeyReasserted(t *testing.T) {
	r, _ := usersRig(t)
	p := filepath.Join(r.root, "home/xdrrecover/.ssh/authorized_keys")
	r.a.accounts(r.snap)
	if len(r.kind("recovery-drift")) != 0 {
		t.Fatal("drift on a good key")
	}
	os.WriteFile(p, []byte("ssh-ed25519 AAAA k\nssh-rsa EVIL attacker\n"), 0o644)
	r.a.accounts(r.snap)
	if b, _ := os.ReadFile(p); string(b) != "ssh-ed25519 AAAA k\n" {
		t.Fatalf("key file %q", b)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if got := r.kind("recovery-drift"); len(got) != 1 || got[0].Severity != model.SevHigh {
		t.Fatalf("drift %+v", got)
	}
}

func TestRecovery_Missing(t *testing.T) {
	r, _ := usersRig(t)
	testfs.File(t, r.root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644)
	r.a.accounts(r.snap)
	r.a.accounts(r.snap)
	if got := r.kind("recovery-missing"); len(got) != 1 || got[0].Severity != model.SevCritical {
		t.Fatalf("missing %+v", got)
	}
}
