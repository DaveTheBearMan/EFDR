package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/testfs"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRun_Version(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || !strings.HasPrefix(out, "xdr ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestRun_Unknown(t *testing.T) {
	code, _, errb := run("bogus")
	if code != 2 || !strings.Contains(errb, `unknown command "bogus"`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestRun_NoArgs(t *testing.T) {
	code, _, errb := run()
	if code != 2 || !strings.Contains(errb, "usage:") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func fixture(t *testing.T) string {
	t.Helper()
	root := testfs.Root(t)
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644)
	testfs.File(t, root, "etc/shadow", "root:*:1::::::\n", 0o640)
	testfs.File(t, root, "etc/group", "root:x:0:\n", 0o644)
	testfs.File(t, root, "etc/hostname", "web01\n", 0o644)
	testfs.File(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n", 0o644)
	testfs.File(t, root, "usr/bin/ls", "ls", 0o755)
	return root
}

func plant(t *testing.T, root string) {
	t.Helper()
	testfs.File(t, root, "etc/cron.d/evil", "* * * * * root /tmp/x\n", 0o644)
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n", 0o644)
	testfs.File(t, root, "etc/ssh/sshd_config", "PermitRootLogin yes\n", 0o644)
}

func capture(t *testing.T, root string, extra ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "b.json.gz")
	if code, _, errb := run(append([]string{"capture", "--root", root, "--out", out}, extra...)...); code != 0 {
		t.Fatalf("capture: %d %s", code, errb)
	}
	return out
}

func TestCaptureThenScan_Clean(t *testing.T) {
	root := fixture(t)
	b := capture(t, root)
	code, out, errb := run("scan", "--root", root, "--baseline", b)
	if code != 0 || out != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errb)
	}
}

func TestCaptureThenScan_Planted(t *testing.T) {
	root := fixture(t)
	b := capture(t, root)
	plant(t, root)
	code, out, _ := run("scan", "--root", root, "--baseline", b)
	if code != 1 {
		t.Fatalf("code=%d out=%q", code, out)
	}
	for _, want := range []string{"CRITICAL\tadded\taccount\ttoor", "CRITICAL\taltered\tsshd\t/etc/ssh/sshd_config", "HIGH\tadded\tcron\t/etc/cron.d/evil", "    +PermitRootLogin yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestScan_JSON(t *testing.T) {
	root := fixture(t)
	b := capture(t, root)
	plant(t, root)
	_, out, _ := run("scan", "--root", root, "--baseline", b, "--json")
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	// 3 planted items + altered /etc/passwd + the new /etc/cron.d directory
	if len(got) != 5 || got[0]["severity"] != "critical" {
		t.Fatalf("%+v", got)
	}
}

func TestScan_LayerCompose(t *testing.T) {
	root := fixture(t)
	base := capture(t, root)
	testfs.File(t, root, "etc/cron.d/organizer", "0 * * * * root /usr/bin/true\n", 0o644)
	triage := capture(t, root, "--layer", "triage")
	code, out, _ := run("scan", "--root", root, "--baseline", base, "--baseline", triage)
	if code != 0 {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestScan_Embedded(t *testing.T) {
	// The placeholder embedded baseline is empty, so every file is "added".
	code, out, _ := run("scan", "--root", fixture(t))
	if code != 1 || !strings.Contains(out, "/etc/ssh/sshd_config") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestPkglist(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "var/lib/dpkg/status", "Package: b\nStatus: install ok installed\nVersion: 2.0\nArchitecture: all\n\nPackage: a\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n", 0o644)
	code, out, _ := run("pkglist", "--root", root)
	if code != 0 || out != "a=1.0 amd64\nb=2.0 all\n" {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestPkghash_EmptyDirErrors(t *testing.T) {
	code, _, errb := run("pkghash", "--debs", t.TempDir(), "--out", filepath.Join(t.TempDir(), "p.json.gz"))
	if code != 2 || !strings.Contains(errb, "no .deb files") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestScan_BadBaseline(t *testing.T) {
	if code, _, _ := run("scan", "--root", t.TempDir(), "--baseline", "/nonexistent"); code != 2 {
		t.Fatalf("code=%d", code)
	}
}
