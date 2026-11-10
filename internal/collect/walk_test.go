package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestWalk_Basic(t *testing.T) {
	root := testfs.Root(t)
	cron := "* * * * * root x\n"
	testfs.File(t, root, "etc/crontab", cron, 0o644)
	testfs.File(t, root, "usr/bin/tool", "bin", 0o755|os.ModeSetuid)
	files, errs := Walk(root)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	c, ok := files["/etc/crontab"]
	if !ok || c.SHA256 != sum(cron) || string(c.Content) != cron || c.Type != baseline.TypeFile {
		t.Fatalf("crontab entry %+v", c)
	}
	tool := files["/usr/bin/tool"]
	if os.FileMode(tool.Mode)&os.ModeSetuid == 0 || tool.Content != nil {
		t.Fatalf("tool entry %+v", tool)
	}
	if _, ok := files["/etc"]; !ok {
		t.Fatal("directories should be recorded")
	}
}

func TestWalk_SymlinkNotFollowed(t *testing.T) {
	root := testfs.Root(t)
	testfs.Symlink(t, root, "etc/cron.d/x", "/dev/zero")
	done := make(chan map[string]baseline.FileEntry)
	go func() { f, _ := Walk(root); done <- f }()
	select {
	case files := <-done:
		e := files["/etc/cron.d/x"]
		if e.Type != baseline.TypeLink || e.Link != "/dev/zero" || e.SHA256 != "" {
			t.Fatalf("entry %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("walk hung on symlink")
	}
}

func TestWalk_FifoAndUnreadable(t *testing.T) {
	root := testfs.Root(t)
	testfs.Fifo(t, root, "tmp/f")
	testfs.File(t, root, "etc/secret", "s", 0)
	done := make(chan struct{})
	var files map[string]baseline.FileEntry
	var errs []string
	go func() { files, errs = Walk(root); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("walk hung on fifo")
	}
	if files["/tmp/f"].Type != baseline.TypeOther {
		t.Fatalf("fifo entry %+v", files["/tmp/f"])
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot test unreadable file")
	}
	if files["/etc/secret"].Err == "" || len(errs) != 1 {
		t.Fatalf("secret %+v errs %v", files["/etc/secret"], errs)
	}
}

func TestWalk_Excluded(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "proc/1/x", "", 0o644)
	testfs.File(t, root, "var/log/a", "", 0o644)
	testfs.File(t, root, "etc/machine-id", "id", 0o644)
	testfs.File(t, root, "etc/ssh/ssh_host_ed25519_key", "k", 0o600)
	testfs.File(t, root, "dev/null2", "", 0o644)
	testfs.File(t, root, "dev/shm/evil", "x", 0o755)
	files, _ := Walk(root)
	for _, p := range []string{"/proc/1/x", "/proc", "/var/log/a", "/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key", "/dev/null2"} {
		if _, ok := files[p]; ok {
			t.Errorf("%s should be excluded", p)
		}
	}
	if _, ok := files["/dev/shm/evil"]; !ok {
		t.Error("/dev/shm/evil should be walked")
	}
}
