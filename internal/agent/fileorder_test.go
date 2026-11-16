package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func reported(t *testing.T, r *rig, path, content string, mode os.FileMode) string {
	t.Helper()
	testfs.File(t, r.root, strings.TrimPrefix(path, "/"), content, mode)
	r.a.scan(false)
	id := FileID(path)
	if _, ok := r.a.driftNew[id]; !ok {
		t.Fatalf("%s was not reported as a new file: %+v", path, r.kind("file-drift"))
	}
	return id
}

func TestFileOrder_RemovesReportedNewFile(t *testing.T) {
	r := scanRig(t)
	id := reported(t, r, "/etc/cron.d/evil", "* * * * * root /tmp/x\n", 0o640)
	r.a.onOrder(order("file", id, "remove"))
	if _, err := os.Lstat(filepath.Join(r.root, "etc/cron.d/evil")); err == nil {
		t.Fatal("the file is still there")
	}
	if got := r.kind("file-removed"); len(got) != 1 || got[0].Path != "/etc/cron.d/evil" {
		t.Fatalf("file-removed: %+v (refused: %+v)", got, r.kind("file-refused"))
	}
	r.a.onOrder(order("file", id, "undo"))
	b, err := os.ReadFile(filepath.Join(r.root, "etc/cron.d/evil"))
	if err != nil || string(b) != "* * * * * root /tmp/x\n" {
		t.Fatalf("restored %q %v", b, err)
	}
	if st, _ := os.Stat(filepath.Join(r.root, "etc/cron.d/evil")); st.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", st.Mode())
	}
	if len(r.kind("file-restored")) != 1 {
		t.Fatalf("file-restored: %+v", r.got)
	}
	if _, err := os.Stat(filepath.Join(r.a.state, "quarantine-files", id)); err == nil {
		t.Fatal("the quarantine entry outlived the undo")
	}
}

func TestFileOrder_Refusals(t *testing.T) {
	r := scanRig(t)
	r.a.pol.Cfg.GuardExes = append(r.a.pol.Cfg.GuardExes, "/opt/svc/run")
	victim := filepath.Join(t.TempDir(), "victim")
	os.WriteFile(victim, []byte("precious\n"), 0o600)

	swapped := reported(t, r, "/etc/cron.d/swapped", "x\n", 0o644)
	changed := reported(t, r, "/etc/cron.d/changed", "x\n", 0o644)
	guarded := reported(t, r, "/opt/svc/run", "bin\n", 0o755)
	// After the reports (a later scan would report the new state): the
	// first is swapped for a symlink, the second rewritten.
	os.Remove(filepath.Join(r.root, "etc/cron.d/swapped"))
	os.Symlink(victim, filepath.Join(r.root, "etc/cron.d/swapped"))
	testfs.File(t, r.root, "etc/cron.d/changed", "something else\n", 0o644)
	r.a.driftNew[FileID("/etc/crontab")] = driftEntry{Path: "/etc/crontab", Type: baseline.TypeFile, SHA256: sha("* * * * * root x\n")}
	testfs.File(t, r.root, "usr/bin/x", "bin\n", 0o755)
	r.a.driftNew[FileID("/usr/bin/x")] = driftEntry{Path: "/usr/bin/x", Type: baseline.TypeFile, SHA256: sha("bin\n")}

	for name, id := range map[string]string{
		"never reported":         "0123456789abcdef",
		"swapped for a symlink":  swapped,
		"changed since reported": changed,
		"a guarded binary":       guarded,
		"a base-image path":      FileID("/etc/crontab"),
		"under /usr/bin":         FileID("/usr/bin/x"),
	} {
		before := len(r.kind("file-refused"))
		r.a.onOrder(order("file", id, "remove"))
		if len(r.kind("file-refused")) != before+1 {
			t.Errorf("%s: not refused", name)
		}
	}
	if len(r.kind("file-removed")) != 0 {
		t.Fatalf("something was removed: %+v", r.kind("file-removed"))
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatal("the symlink's target was touched")
	}
	for _, p := range []string{"etc/cron.d/changed", "opt/svc/run", "etc/crontab", "usr/bin/x"} {
		if _, err := os.Lstat(filepath.Join(r.root, p)); err != nil {
			t.Errorf("%s is gone: %v", p, err)
		}
	}
}

func TestFileOrder_PurgesOld(t *testing.T) {
	r := scanRig(t)
	r.snap = tree()
	q := filepath.Join(r.a.state, "quarantine-files")
	for id, age := range map[string]time.Duration{"aaaaaaaaaaaaaaaa": 25 * time.Hour, "bbbbbbbbbbbbbbbb": time.Hour} {
		os.MkdirAll(filepath.Join(q, id), 0o700)
		os.WriteFile(filepath.Join(q, id, "data"), []byte("x"), 0o600)
		meta, _ := json.Marshal(map[string]any{"Path": "/etc/x", "At": r.now.Add(-age)})
		os.WriteFile(filepath.Join(q, id, "meta.json"), meta, 0o600)
	}
	r.a.sweep()
	if _, err := os.Stat(filepath.Join(q, "aaaaaaaaaaaaaaaa")); err == nil {
		t.Error("a 25 h old entry was kept")
	}
	if _, err := os.Stat(filepath.Join(q, "bbbbbbbbbbbbbbbb")); err != nil {
		t.Error("a 1 h old entry was purged")
	}
}
