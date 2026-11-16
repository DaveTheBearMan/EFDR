package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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
	r.a.snap = r.snap
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

// A user owns the directory the key file is written into: a symlink there
// must never make the agent (root) write somewhere else.
func TestWriteKeys_NoSymlinkFollow(t *testing.T) {
	r, _ := usersRig(t)
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("precious\n"), 0o600)
	home := filepath.Join(r.root, "home/xdrrecover")

	// A planted temp name does nothing: the temp file is not at a fixed name.
	os.Symlink(victim, filepath.Join(home, ".ssh/authorized_keys.xdr-tmp"))
	os.WriteFile(filepath.Join(home, ".ssh/authorized_keys"), []byte("junk\n"), 0o600)
	r.a.accounts(r.snap)
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatalf("victim overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".ssh/authorized_keys")); string(b) != "ssh-ed25519 AAAA k\n" {
		t.Fatalf("keys not restored: %q", b)
	}

	// .ssh itself a symlink to another directory: refused, nothing written there.
	other := t.TempDir()
	os.RemoveAll(filepath.Join(home, ".ssh"))
	os.Symlink(other, filepath.Join(home, ".ssh"))
	r.a.recoverySaid = false
	r.a.accounts(r.snap)
	if ents, _ := os.ReadDir(other); len(ents) != 0 {
		t.Fatalf("wrote through a .ssh symlink: %v", ents)
	}
	got := r.kind("recovery-drift")
	if len(got) < 2 || got[len(got)-1].Action != "alert" {
		t.Fatalf("a refused write should be an alert: %+v", got)
	}

	// authorized_keys itself a symlink: replaced, not followed.
	os.Remove(filepath.Join(home, ".ssh"))
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.Symlink(victim, filepath.Join(home, ".ssh/authorized_keys"))
	r.a.accounts(r.snap)
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatalf("victim overwritten through authorized_keys: %q", b)
	}
	if st, _ := os.Lstat(filepath.Join(home, ".ssh/authorized_keys")); st.Mode()&os.ModeSymlink != 0 {
		t.Fatal("symlink left in place")
	}
}

// The temp file is made fresh (O_EXCL, a name nobody can plant): a user
// who plants something at the old fixed name cannot block the repair.
func TestWriteKeys_PlantedTempNameCannotBlock(t *testing.T) {
	r, _ := usersRig(t)
	home := filepath.Join(r.root, "home/xdrrecover/.ssh")
	os.WriteFile(filepath.Join(home, "authorized_keys"), []byte("junk\n"), 0o600)
	plant := filepath.Join(home, "authorized_keys.xdr-tmp")
	os.MkdirAll(filepath.Join(plant, "x"), 0o700)
	r.a.accounts(r.snap)
	if b, _ := os.ReadFile(filepath.Join(home, "authorized_keys")); string(b) != "ssh-ed25519 AAAA k\n" {
		t.Fatalf("repair blocked by a planted name: %q; %+v", b, r.kind("recovery-drift"))
	}
	if ents, _ := os.ReadDir(home); len(ents) != 2 { // authorized_keys and the planted directory
		t.Fatalf("temp file left behind: %v", ents)
	}
}

// A pause turns automatic actions into alerts: a new login account made
// during one is told, not locked; it is judged as usual once the pause ends.
func TestUsers_PauseAlertsInsteadOfLocking(t *testing.T) {
	r, ran := usersRig(t)
	r.a.pausedUntil = r.now.Add(time.Hour)
	r.a.accounts(r.snap)
	r.a.accounts(r.snap)
	if um := usermods(*ran); len(um) != 0 {
		t.Fatalf("locked during a pause: %v", um)
	}
	var told []string
	for _, in := range r.kind("user-new") {
		if strings.Contains(in.Detail, "paused") {
			told = append(told, in.User)
		}
	}
	if !slices.Equal(told, []string{"evil"}) {
		t.Fatalf("told paused: %v", told)
	}
	r.now = r.now.Add(2 * time.Hour)
	r.a.accounts(r.snap)
	if um := usermods(*ran); len(um) != 1 || um[0][1] != "--lock" {
		t.Fatalf("after the pause: %v", um)
	}
}
