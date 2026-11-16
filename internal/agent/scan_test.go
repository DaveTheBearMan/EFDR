package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/incident"
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

// The agent rewrites sshd_config and pam.d/sshd itself (the gate), and the
// resolver files with dns.pin: that is not drift for an operator to look at
// (assertSSH reports a change nobody asked for as ssh-drift).
func TestScan_FilesTheAgentManagesAreNotDrift(t *testing.T) {
	r := scanRig(t)
	r.a.pol.Base.Files[pathenc.Encode("/etc/pam.d/sshd")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base pam")}
	r.a.pol.Base.Files[pathenc.Encode("/etc/ssh/sshd_config")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base sshd")}
	r.a.pol.Base.Files[pathenc.Encode("/etc/pam.d/login")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base login")}
	testfs.File(t, r.root, "etc/pam.d/sshd", "rendered pam", 0o644)
	testfs.File(t, r.root, "etc/ssh/sshd_config", "rendered sshd", 0o644)
	testfs.File(t, r.root, "etc/pam.d/login", "tampered login", 0o644)
	paths := func() map[string]bool {
		m := map[string]bool{}
		for _, in := range r.kind("file-drift") {
			m[in.Path] = true
		}
		return m
	}
	r.a.scan(false)
	if got := paths(); !got["/etc/pam.d/sshd"] || !got["/etc/ssh/sshd_config"] {
		t.Fatalf("without the gate these are drift: %v", got)
	}
	r = scanRig(t)
	r.a.pol.Base.Files[pathenc.Encode("/etc/pam.d/sshd")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base pam")}
	r.a.pol.Base.Files[pathenc.Encode("/etc/ssh/sshd_config")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base sshd")}
	r.a.pol.Base.Files[pathenc.Encode("/etc/pam.d/login")] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("base login")}
	testfs.File(t, r.root, "etc/pam.d/sshd", "rendered pam", 0o644)
	testfs.File(t, r.root, "etc/ssh/sshd_config", "rendered sshd", 0o644)
	testfs.File(t, r.root, "etc/pam.d/login", "tampered login", 0o644)
	r.a.cfg.SSH = &config.SSH{Blue: []string{"alice"}}
	r.a.scan(false)
	got := paths()
	if got["/etc/pam.d/sshd"] || got["/etc/ssh/sshd_config"] {
		t.Fatalf("the gate's own files were reported: %v", got)
	}
	if !got["/etc/pam.d/login"] {
		t.Fatalf("another pam file must still be reported: %v", got)
	}
}

// Files in /tmp and /home that nothing classifies are the box's everyday
// traffic, and an incident each would get the host disabled for flooding.
func TestScan_UnclassifiedNewFilesAreNotReported(t *testing.T) {
	r := scanRig(t)
	for i := 0; i < 700; i++ {
		testfs.File(t, r.root, fmt.Sprintf("tmp/x%03d", i), "x", 0o644)
	}
	testfs.File(t, r.root, "etc/cron.d/evil", "* * * * * root /tmp/x\n", 0o644)
	r.a.scan(false)
	n := 0
	var cron bool
	for _, in := range r.kind("file-drift") {
		if strings.HasPrefix(in.Path, "/tmp/") {
			n++
		}
		cron = cron || in.Path == "/etc/cron.d/evil"
	}
	if n != 0 || !cron {
		t.Fatalf("%d /tmp files reported, cron file reported: %v", n, cron)
	}
}

// One scan reports a bounded number; the rest follow on the next scans, and
// one line says that more are waiting.
func TestScan_CapPerScan(t *testing.T) {
	r := scanRig(t)
	for i := 0; i < 100; i++ {
		testfs.File(t, r.root, fmt.Sprintf("etc/cron.d/f%03d", i), fmt.Sprintf("job %d\n", i), 0o644)
	}
	count := func() int {
		n := 0
		for _, in := range r.kind("file-drift") {
			if strings.HasPrefix(in.Path, "/etc/cron.d/") {
				n++
			}
		}
		return n
	}
	r.a.scan(false)
	if n := count(); n > scanCap {
		t.Fatalf("one scan reported %d, cap %d", n, scanCap)
	}
	var summary bool
	for _, in := range r.kind("file-drift") {
		summary = summary || (in.Path == "" && strings.Contains(in.Detail, "more findings"))
	}
	if !summary {
		t.Fatalf("no summary line: %+v", r.kind("file-drift"))
	}
	for i := 0; i < 6; i++ {
		r.a.scan(false)
	}
	if n := count(); n != 100 {
		t.Fatalf("after seven scans %d of 100 reported", n)
	}
}

// Unclassified altered or removed files cannot use up the memory that a
// real finding needs.
func TestScan_NoiseCannotBlindTheReport(t *testing.T) {
	r := scanRig(t)
	for i := 0; i < maxDrift+500; i++ {
		r.a.pol.Base.Files[pathenc.Encode(fmt.Sprintf("/srv/a%05d", i))] = baseline.FileEntry{Type: baseline.TypeFile, Mode: 0o644, SHA256: sha("x")}
	}
	for i := 0; i < 60; i++ {
		r.a.scan(false)
	}
	if len(r.a.drift) > maxDrift {
		t.Fatalf("%d remembered", len(r.a.drift))
	}
	testfs.File(t, r.root, "etc/cron.d/late", "* * * * * root /tmp/y\n", 0o644)
	r.a.scan(false)
	found := false
	for _, in := range r.kind("file-drift") {
		found = found || in.Path == "/etc/cron.d/late"
	}
	if !found {
		t.Fatal("a real finding was not reported after the noise filled the memory")
	}
}

// A scan's findings are written with the agent's lock free: the sweep and
// the gate do not wait on the log and the fleet queue.
func TestScan_RecordsWithoutTheLock(t *testing.T) {
	r := scanRig(t)
	for i := 0; i < 5; i++ {
		testfs.File(t, r.root, fmt.Sprintf("etc/cron.d/evil%d", i), "* * * * * root /tmp/x\n", 0o644)
	}
	held := 0
	onWrite := r.a.log.OnWrite
	r.a.log.OnWrite = func(in incident.Incident) {
		if in.Kind == "file-drift" {
			if r.a.mu.TryLock() {
				r.a.mu.Unlock()
			} else {
				held++
			}
		}
		onWrite(in)
	}
	r.a.scan(false)
	if n := len(r.kind("file-drift")); n < 5 || held != 0 {
		t.Fatalf("%d findings, %d written under the lock", n, held)
	}
}

// The fast scan keeps its hashes for the next one.
func TestScan_FastScanCachesHashes(t *testing.T) {
	r := scanRig(t)
	r.a.scan(false)
	if r.a.hashCache == nil || r.a.hashCache.Len() == 0 {
		t.Fatal("no hash cache after a fast scan")
	}
}
