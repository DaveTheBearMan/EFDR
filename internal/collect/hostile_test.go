package collect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func has(files map[string]baseline.FileEntry, p string) bool { _, ok := files[p]; return ok }

// The trees that churn on a healthy box are not inventoried file by file,
// but nothing privileged or persistence-relevant may hide in them.
func TestWalk_VolatileKeepsPrivilegedAndPersistence(t *testing.T) {
	root := testfs.Root(t)
	suid := []string{"/var/cache/.x", "/var/log/.x", "/tmp/systemd-private-evil/x", "/var/lib/mysql/.x", "/var/spool/postfix/.x", "/run/user/0/.x"}
	for _, p := range suid {
		testfs.File(t, root, p[1:], "payload", 0o755|os.ModeSetuid)
	}
	testfs.File(t, root, "var/log/syslog", "noise", 0o640)
	testfs.File(t, root, "var/lib/mysql/.ssh/authorized_keys", "ssh-ed25519 AAAA evil\n", 0o600)
	testfs.File(t, root, "var/lib/cloud/scripts/per-boot/x.sh", "#!/bin/sh\n", 0o755)
	testfs.File(t, root, "run/user/1000/systemd/user/x.service", "[Service]\n", 0o644)
	files, _ := Walk(root)
	for _, p := range suid {
		e := files[p]
		if os.FileMode(e.Mode)&os.ModeSetuid == 0 || e.SHA256 != sum("payload") {
			t.Errorf("%s: setuid file must be recorded, got %+v", p, e)
		}
	}
	for _, p := range []string{"/var/log/syslog", "/var/log", "/var/lib/mysql"} {
		if has(files, p) {
			t.Errorf("%s: plain entries in volatile trees are not inventoried", p)
		}
	}
	for _, p := range []string{"/var/lib/mysql/.ssh/authorized_keys", "/var/lib/cloud/scripts/per-boot/x.sh", "/run/user/1000/systemd/user/x.service"} {
		if e := files[p]; e.Content == nil {
			t.Errorf("%s: persistence path must be recorded with content, got %+v", p, e)
		}
	}
}

func TestWalk_IgnoredDropsOnlyPlainFiles(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/adjtime", "x", 0o644)
	testfs.File(t, root, "etc/ssh/ssh_host_ed25519_key", "k", 0o600)
	testfs.File(t, root, "etc/ssh/ssh_host_x", "payload", 0o755|os.ModeSetuid)
	testfs.Symlink(t, root, "etc/machine-id", "/tmp/x")
	testfs.File(t, root, "etc/cloud/cloud.cfg.d/99.cfg", "bootcmd: [x]\n", 0o644)
	testfs.File(t, root, "etc/ld.so.cache", "cache", 0o644)
	files, _ := Walk(root)
	for _, p := range []string{"/etc/adjtime", "/etc/ssh/ssh_host_ed25519_key"} {
		if has(files, p) {
			t.Errorf("%s: plain identity file should be dropped", p)
		}
	}
	if e := files["/etc/ssh/ssh_host_x"]; os.FileMode(e.Mode)&os.ModeSetuid == 0 {
		t.Errorf("setuid file under an ignored name must be recorded, got %+v", e)
	}
	if e := files["/etc/machine-id"]; e.Type != baseline.TypeLink {
		t.Errorf("symlink under an ignored name must be recorded, got %+v", e)
	}
	if e := files["/etc/cloud/cloud.cfg.d/99.cfg"]; string(e.Content) != "bootcmd: [x]\n" {
		t.Errorf("cloud-init config must be recorded with content, got %+v", e)
	}
	if !has(files, "/etc/ld.so.cache") {
		t.Error("/etc/ld.so.cache steers library loading and must be recorded")
	}
}

func TestWalk_DevRegularFilesRecorded(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "dev/.hid/payload", "x", 0o755)
	testfs.Fifo(t, root, "dev/initctl")
	testfs.File(t, root, "dev/shm/evil", "x", 0o755)
	files, _ := Walk(root)
	if !has(files, "/dev/.hid/payload") || !has(files, "/dev/shm/evil") {
		t.Errorf("regular files under /dev must be recorded: %v", files)
	}
	for _, p := range []string{"/dev", "/dev/.hid", "/dev/initctl"} {
		if has(files, p) {
			t.Errorf("%s: device-tree furniture should not be recorded", p)
		}
	}
}

func TestWalk_SealedAndSkipped(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "var/lib/docker/overlay2/a/b", "x", 0o644)
	testfs.File(t, root, "proc/1/x", "", 0o644)
	testfs.File(t, root, "sys/kernel/x", "", 0o644)
	files, _ := Walk(root)
	if files["/var/lib/docker"].Type != baseline.TypeDir {
		t.Error("/var/lib/docker itself must be recorded")
	}
	for _, p := range []string{"/var/lib/docker/overlay2", "/var/lib/docker/overlay2/a/b", "/proc", "/proc/1/x", "/sys", "/sys/kernel/x"} {
		if has(files, p) {
			t.Errorf("%s should not be walked", p)
		}
	}
}

func TestWalk_SymlinkToDirNotDescended(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "srv/real/inside", "x", 0o644)
	testfs.Symlink(t, root, "etc/cron.d", filepath.Join(root, "srv/real"))
	files, _ := Walk(root)
	if e := files["/etc/cron.d"]; e.Type != baseline.TypeLink {
		t.Fatalf("entry %+v", e)
	}
	if has(files, "/etc/cron.d/inside") {
		t.Fatal("walk descended through a symlink")
	}
}

// deepDir builds a directory chain under root whose full path exceeds
// PATH_MAX and drops a setuid file at the bottom.
func deepDir(t *testing.T, root string) {
	t.Helper()
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("d", 250)
	for i := 0; i < 20; i++ {
		if err := unix.Mkdirat(fd, name, 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		fd = next
	}
	f, err := unix.Openat(fd, "payload", unix.O_CREAT|unix.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	unix.Fchmod(f, 0o4755)
	unix.Close(f)
	unix.Close(fd)
}

func TestWalk_UnreachableDepthIsAnErrorEntry(t *testing.T) {
	root := testfs.Root(t)
	deepDir(t, root)
	files, _ := Walk(root)
	n := 0
	for _, e := range files {
		if e.Err != "" {
			n++
		}
	}
	if n == 0 {
		t.Fatal("a directory the walk could not enter must leave an entry carrying the error")
	}
}

// Files appearing and vanishing during a walk are normal on a live box
// and must never be reported as errors.
func TestWalk_ChurnIsNotAnError(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "srv/keep", "x", 0o644)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		p := filepath.Join(root, "srv/churn")
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.WriteFile(p, []byte("x"), 0o644)
			os.Remove(p)
		}
	}()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		files, errs := Walk(root)
		if len(errs) != 0 || files["/srv/churn"].Err != "" {
			close(stop)
			<-done
			t.Fatalf("churn reported as error: %v %+v", errs, files["/srv/churn"])
		}
	}
	close(stop)
	<-done
}
