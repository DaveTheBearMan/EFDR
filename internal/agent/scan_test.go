package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/model"
	"xdr/internal/pathenc"
	"xdr/internal/testfs"
)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func scanRig(t *testing.T) *rig {
	r := newRig(t)
	r.a.pol.Base = &baseline.Baseline{Files: map[string]baseline.FileEntry{
		pathenc.Encode("/etc/crontab"):   {Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("* * * * * root x\n"), Content: []byte("* * * * * root x\n")},
		pathenc.Encode("/usr/bin/tool"):  {Type: baseline.TypeFile, Mode: 0o755, SHA256: sha("bin")},
		pathenc.Encode("/etc/gone.conf"): {Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("old")},
	}}
	testfs.File(t, r.root, "etc/crontab", "* * * * * root x\n", 0o644)
	testfs.File(t, r.root, "usr/bin/tool", "bin", 0o755)
	return r
}

func TestScan_ReportsNewFileOnce(t *testing.T) {
	r := scanRig(t)
	r.a.scan(false)
	n := len(r.kind("file-drift"))
	testfs.File(t, r.root, "etc/cron.d/evil", "* * * * * root /tmp/x\n", 0o644)
	r.a.scan(false)
	got := r.kind("file-drift")
	var evil []int
	for i, in := range got {
		if in.Path == "/etc/cron.d/evil" {
			evil = append(evil, i)
		}
	}
	if len(evil) != 1 || got[evil[0]].Severity < model.SevHigh || got[evil[0]].SHA256 != sha("* * * * * root /tmp/x\n") || got[evil[0]].Action != "alert" {
		t.Fatalf("new file: %+v", got)
	}
	r.a.scan(false)
	if len(r.kind("file-drift")) != len(got) {
		t.Fatalf("reported again with no change: %d then %d (first scan had %d)", len(got), len(r.kind("file-drift")), n)
	}
	testfs.File(t, r.root, "etc/cron.d/evil", "* * * * * root /tmp/y\n", 0o644)
	r.a.scan(false)
	if len(r.kind("file-drift")) != len(got)+1 {
		t.Fatalf("a changed file was not reported again")
	}
	os.Remove(filepath.Join(r.root, "etc/cron.d/evil"))
	r.a.scan(false)
	if _, ok := r.a.drift["/etc/cron.d/evil"]; ok {
		t.Fatal("a file that is gone is still remembered as reported")
	}
	testfs.File(t, r.root, "etc/cron.d/evil", "* * * * * root /tmp/y\n", 0o644)
	r.a.scan(false)
	if _, ok := r.a.drift["/etc/cron.d/evil"]; !ok {
		t.Fatal("a file that came back is not reported again")
	}
}

func TestScan_PartialDoesNotReadRemoved(t *testing.T) {
	r := scanRig(t)
	os.Remove(filepath.Join(r.root, "usr/bin/tool")) // outside the fast walk
	r.a.scan(false)
	for _, in := range r.kind("file-drift") {
		if in.Path == "/usr/bin/tool" {
			t.Fatalf("a fast scan reported a file it did not walk: %+v", in)
		}
	}
	found := false
	for _, in := range r.kind("file-drift") {
		found = found || in.Path == "/etc/gone.conf"
	}
	if !found {
		t.Fatalf("a removed file under /etc was not reported: %+v", r.kind("file-drift"))
	}
	r.a.scan(true)
	found = false
	for _, in := range r.kind("file-drift") {
		found = found || in.Path == "/usr/bin/tool"
	}
	if !found {
		t.Fatal("the full scan did not report the removed binary")
	}
}

func TestScan_Bounded(t *testing.T) {
	r := scanRig(t)
	for i := 0; i < 5000; i++ {
		testfs.File(t, r.root, fmt.Sprintf("etc/cron.d/f%04d", i), "x", 0o644)
	}
	r.a.scan(false)
	if len(r.a.drift) > maxDrift {
		t.Fatalf("%d remembered", len(r.a.drift))
	}
}
