package collect

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func snapshotT(t *testing.T, root string) *baseline.Baseline {
	t.Helper()
	type res struct {
		b   *baseline.Baseline
		err error
	}
	done := make(chan res, 1)
	go func() { b, err := Snapshot(root); done <- res{b, err} }()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.b
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot hung")
		return nil
	}
}

func errorsMention(b *baseline.Baseline, p string) bool {
	for _, e := range b.Errors {
		if strings.HasPrefix(e, p+": ") {
			return true
		}
	}
	return false
}

// The files a snapshot reads by name belong to the adversary: none may be
// followed as a symlink, block as a fifo, or be read without bound.
func TestSnapshot_HostileIdentityFiles(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "srv/decoy", "decoy\n", 0o644)
	testfs.Symlink(t, root, "etc/hostname", "../srv/decoy")
	testfs.Fifo(t, root, "etc/passwd")
	testfs.Fifo(t, root, "etc/group")
	testfs.Fifo(t, root, "etc/os-release")
	testfs.Fifo(t, root, "proc/modules")
	b := snapshotT(t, root)
	if b.Host != "" || b.OSRelease != "" || b.Accounts != nil || b.Groups != nil || b.Modules != nil {
		t.Fatalf("hostile files were read: %+v", b)
	}
	for _, p := range []string{"/etc/hostname", "/etc/passwd", "/etc/group", "/proc/modules"} {
		if !errorsMention(b, p) {
			t.Errorf("no error recorded for %s: %v", p, b.Errors)
		}
	}
}

func TestSnapshot_OversizeIdentityFile(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/hostname", strings.Repeat("h", 1<<20), 0o644)
	b := snapshotT(t, root)
	if b.Host != "" || !errorsMention(b, "/etc/hostname") {
		t.Fatalf("host %d bytes, errors %v", len(b.Host), b.Errors)
	}
}

func TestSnapshot_ShadowFifoKeepsAccounts(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644)
	testfs.Fifo(t, root, "etc/shadow")
	b := snapshotT(t, root)
	if len(b.Accounts) != 1 || !errorsMention(b, "/etc/shadow") {
		t.Fatalf("accounts %+v errors %v", b.Accounts, b.Errors)
	}
}

func TestSnapshot_OSReleaseUbuntuLayout(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "usr/lib/os-release", "VERSION=\"24.04.3 LTS (Noble Numbat)\"\n", 0o644)
	testfs.Symlink(t, root, "etc/os-release", "../usr/lib/os-release")
	if b := snapshotT(t, root); b.OSRelease != "24.04.3 LTS (Noble Numbat)" || len(b.Errors) != 0 {
		t.Fatalf("os %q errors %v", b.OSRelease, b.Errors)
	}
}

func TestSnapshot_AbsentFilesAreNotErrors(t *testing.T) {
	if b := snapshotT(t, testfs.Root(t)); len(b.Errors) != 0 || b.Accounts != nil {
		t.Fatalf("%+v", b)
	}
}

func TestSnapshot_EmptyPasswdIsCapturedEmpty(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/passwd", "", 0o644)
	testfs.File(t, root, "etc/group", "", 0o644)
	if b := snapshotT(t, root); b.Accounts == nil || b.Groups == nil {
		t.Fatal("an opened but empty database is captured (non-nil), not skipped")
	}
}

func TestSnapshot_RootForms(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/crontab", "x\n", 0o644)
	if _, err := Snapshot(filepath.Join(root, "missing")); err == nil {
		t.Error("missing root must be an error")
	}
	if _, err := Snapshot(filepath.Join(root, "etc/crontab")); err == nil {
		t.Error("a root that is not a directory must be an error")
	}
	link := filepath.Join(t.TempDir(), "link")
	testfs.Symlink(t, filepath.Dir(link), "link", root)
	if b, err := Snapshot(link); err != nil || !has(b.Files, "/etc/crontab") {
		t.Errorf("symlinked root: err=%v files=%d", err, len(b.Files))
	}
	t.Chdir(filepath.Dir(root))
	for _, rel := range []string{filepath.Base(root), "./" + filepath.Base(root) + "/"} {
		if b, err := Snapshot(rel); err != nil || !has(b.Files, "/etc/crontab") {
			t.Errorf("relative root %q: err=%v", rel, err)
		}
	}
	t.Chdir(root)
	if b, err := Snapshot("."); err != nil || !has(b.Files, "/etc/crontab") {
		t.Errorf("root \".\": err=%v", err)
	}
}
