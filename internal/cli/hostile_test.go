package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/testfs"
)

// The operator reads scan output on a terminal. Names, link targets and file
// contents come from the adversary and must not be able to drive it.
func TestScan_TextOutputCannotDriveTheTerminal(t *testing.T) {
	root := fixture(t)
	testfs.Symlink(t, root, "etc/alt", "x")
	b := capture(t, root)
	testfs.File(t, root, "etc/cron.d/a\x1b[2Kb\rc\td", "x\n", 0o644)
	testfs.Remove(t, root, "etc/alt")
	testfs.Symlink(t, root, "etc/alt", "\x1b[1A\u202egnp")
	testfs.File(t, root, "etc/ssh/sshd_config", "PermitRootLogin yes\x1b[2K\r\x07\n\tindented\n", 0o644)
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nev\x1bil\x7f:x:0:0:::\n", 0o644)
	code, out, _ := run("scan", "--root", root, "--baseline", b)
	if code != 1 {
		t.Fatalf("code=%d", code)
	}
	for _, bad := range []string{"\x1b", "\r", "\x07", "\x7f", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains raw %q:\n%q", bad, out)
		}
	}
	for _, want := range []string{
		`HIGH	added	cron	/etc/cron.d/a\x1b[2Kb\rc\td	new file`,
		`MEDIUM	altered	file	/etc/alt	link x→\x1b[1A\u202egnp`,
		`CRITICAL	added	account	ev\x1bil\x7f	`,
		`    +PermitRootLogin yes\x1b[2K\r\a`,
		"    +\tindented", // tabs are kept in diff bodies, where no columns follow
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.HasPrefix(line, "    ") && strings.Count(line, "\t") != 4 {
			t.Errorf("finding line does not have 5 columns: %q", line)
		}
	}
}

// A baseline describes the whole box; only its owner reads it, and it never
// holds password hashes.
func TestCapture_BaselineIsPrivate(t *testing.T) {
	root := fixture(t)
	testfs.File(t, root, "etc/shadow", "root:$6$SALT$SECRETHASH:1::::::\n", 0o640)
	out := filepath.Join(t.TempDir(), "b.json.gz")
	if err := os.WriteFile(out, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{out, filepath.Join(t.TempDir(), "new.json.gz")} {
		if code, _, errb := run("capture", "--root", root, "--out", name); code != 0 {
			t.Fatalf("capture: %d %s", code, errb)
		}
		st, err := os.Stat(name)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want 0600 (%v)", name, st.Mode(), err)
		}
		b, err := readBaseline(name)
		if err != nil {
			t.Fatal(err)
		}
		if e := b.Files["/etc/shadow"]; e.SHA256 == "" || e.Content != nil {
			t.Fatalf("shadow entry %+v", e)
		}
		if b.Files["/etc/passwd"].Content == nil {
			t.Fatal("passwd content should be kept for diffs")
		}
	}
}

func TestRun_MissingRootIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	b := capture(t, fixture(t))
	for _, args := range [][]string{
		{"scan", "--root", missing, "--baseline", b},
		{"capture", "--root", missing, "--out", filepath.Join(t.TempDir(), "o")},
	} {
		if code, out, errb := run(args...); code != 2 || !strings.Contains(errb, "nope") {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errb)
		}
	}
}

func TestUnreadableFile_WarnedAtCaptureAndFoundAtScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	root := fixture(t)
	testfs.File(t, root, "srv/secret", "x", 0o000)
	out := filepath.Join(t.TempDir(), "b.json.gz")
	code, _, errb := run("capture", "--root", root, "--out", out)
	if code != 0 || !strings.Contains(errb, "warning: /srv/secret: permission denied") {
		t.Fatalf("capture: code=%d err=%q", code, errb)
	}
	code, stdout, _ := run("scan", "--root", root, "--baseline", out)
	if code != 1 || stdout != "HIGH\terror\tfile\t/srv/secret\tcould not read: permission denied\n" {
		t.Fatalf("scan: code=%d out=%q", code, stdout)
	}
}

func TestCapture_WarnsAboutUnreadableDatabases(t *testing.T) {
	root := fixture(t)
	testfs.Remove(t, root, "etc/group")
	testfs.Fifo(t, root, "etc/group")
	_, _, errb := run("capture", "--root", root, "--out", filepath.Join(t.TempDir(), "b"))
	if !strings.Contains(errb, "warning: /etc/group: not a regular file") {
		t.Fatalf("err=%q", errb)
	}
}

func TestPkglist_HostileStatusFile(t *testing.T) {
	root := testfs.Root(t)
	testfs.Fifo(t, root, "var/lib/dpkg/status")
	done := make(chan int, 1)
	go func() {
		code, _, _ := run("pkglist", "--root", root)
		done <- code
	}()
	select {
	case code := <-done:
		if code != 2 {
			t.Fatalf("code=%d", code)
		}
	case <-time.After(5 * time.Second):
		// Unblock the reader so the test binary can exit.
		if f, err := os.OpenFile(filepath.Join(root, "var/lib/dpkg/status"), os.O_WRONLY, 0); err == nil {
			f.Close()
		}
		t.Fatal("pkglist blocked on a fifo")
	}
}

// Names and link targets are arbitrary bytes; they must compare equal to
// themselves after a baseline is saved and loaded.
func TestCaptureThenScan_OddBytes(t *testing.T) {
	root := fixture(t)
	testfs.File(t, root, "srv/a\xffb", "one", 0o644)
	testfs.Symlink(t, root, "srv/link", "tar\xfeget")
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nsv\xffc:x:9:9::/h\xff:/bin/sh\n", 0o644)
	testfs.File(t, root, "etc/group", "root:x:0:\ngr\xff:x:9:m\xfe\n", 0o644)
	b := capture(t, root)
	if code, out, _ := run("scan", "--root", root, "--baseline", b); code != 0 {
		t.Fatalf("phantom findings:\n%s", out)
	}
	testfs.File(t, root, "srv/a\xffb", "two", 0o644)
	code, out, _ := run("scan", "--root", root, "--baseline", b)
	if code != 1 || !strings.HasPrefix(out, "MEDIUM\taltered\tfile\tb64:") || strings.Count(out, "\n") != 1 {
		t.Fatalf("code=%d out=%q", code, out)
	}
}
