package diff

import (
	"os"
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/model"
)

func bl(files map[string]baseline.FileEntry) *baseline.Baseline {
	return &baseline.Baseline{Schema: 1, Files: files}
}

func reg(sha string, mode os.FileMode, content string) baseline.FileEntry {
	e := baseline.FileEntry{Type: baseline.TypeFile, Mode: uint32(mode), SHA256: sha}
	if content != "" {
		e.Content = []byte(content)
	}
	return e
}

func one(t *testing.T, fs []model.Finding) model.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestDiff_AddedCron(t *testing.T) {
	f := one(t, Diff(bl(map[string]baseline.FileEntry{}), bl(map[string]baseline.FileEntry{"/etc/cron.d/evil": reg("a", 0o644, "x")})))
	if f.Kind != model.KindAdded || f.Category != "cron" || f.Severity != model.SevHigh || f.Subject != "/etc/cron.d/evil" || f.After != "a" {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_AlteredSshdHasUnifiedDiff(t *testing.T) {
	p := "/etc/ssh/sshd_config"
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: reg("1", 0o644, "PasswordAuthentication no\n")}),
		bl(map[string]baseline.FileEntry{p: reg("2", 0o644, "PasswordAuthentication yes\n")})))
	if f.Kind != model.KindAltered || f.Category != "sshd" || f.Severity != model.SevCritical || f.Before != "1" || f.After != "2" {
		t.Fatalf("%+v", f)
	}
	if !strings.Contains(f.Diff, "-PasswordAuthentication no") || !strings.Contains(f.Diff, "+PasswordAuthentication yes") {
		t.Fatalf("diff %q", f.Diff)
	}
}

func TestDiff_SuidGainedIsPrivilege(t *testing.T) {
	p := "/usr/bin/find"
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: reg("1", 0o755, "")}), bl(map[string]baseline.FileEntry{p: reg("1", 0o755|os.ModeSetuid, "")})))
	if f.Category != "privilege" || f.Severity != model.SevCritical || !strings.Contains(f.Detail, "mode") {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_CapsGainedIsPrivilege(t *testing.T) {
	p := "/usr/bin/python3.12"
	live := reg("1", 0o755, "")
	live.Caps = "0100000280"
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: reg("1", 0o755, "")}), bl(map[string]baseline.FileEntry{p: live})))
	if f.Category != "privilege" || f.Severity != model.SevCritical || !strings.Contains(f.Detail, "caps") {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_NewSuidInTmp(t *testing.T) {
	f := one(t, Diff(bl(map[string]baseline.FileEntry{}), bl(map[string]baseline.FileEntry{"/var/tmp/.x": reg("a", 0o755|os.ModeSetuid, "")})))
	if f.Category != "privilege" || f.Severity != model.SevCritical {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_HashOnlyIgnoresMode(t *testing.T) {
	p := "/usr/sbin/postfix"
	base := reg("1", 0o755, "")
	base.HashOnly = true
	live := reg("1", 0o700, "")
	live.UID = 5
	if fs := Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{p: live})); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestDiff_Removed(t *testing.T) {
	f := one(t, Diff(bl(map[string]baseline.FileEntry{"/etc/sudoers.d/ok": reg("1", 0o440, "x")}), bl(map[string]baseline.FileEntry{})))
	if f.Kind != model.KindRemoved || f.Category != "sudo" || f.Severity != model.SevHigh || f.Before != "1" {
		t.Fatalf("%+v", f)
	}
}

// What could not be read could not be compared: that is a finding, never
// a silent pass.
func TestDiff_UnreadableLiveEntryIsFinding(t *testing.T) {
	live := reg("", 0o600, "")
	live.Err = "permission denied"
	for p, want := range map[string]model.Severity{"/srv/deep": model.SevHigh, "/etc/sudoers.d/x": model.SevCritical} {
		for _, base := range []map[string]baseline.FileEntry{{}, {p: reg("1", 0o600, "")}, {p: live}} {
			f := one(t, Diff(bl(base), bl(map[string]baseline.FileEntry{p: live})))
			if f.Kind != model.KindError || f.Severity != want || f.Subject != p || !strings.Contains(f.Detail, "permission denied") {
				t.Fatalf("%+v", f)
			}
		}
	}
}

func TestDiff_UnreadableBaseEntryCountsAsAbsent(t *testing.T) {
	p := "/etc/cron.d/x"
	base := reg("", 0o600, "")
	base.Err = "permission denied"
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{p: reg("1", 0o600, "x")})))
	if f.Kind != model.KindAdded || f.Category != "cron" {
		t.Fatalf("%+v", f)
	}
	f = one(t, Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{})))
	if f.Kind != model.KindRemoved {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_CollectorErrorsAreFindings(t *testing.T) {
	live := bl(map[string]baseline.FileEntry{})
	live.Errors = []string{"/etc/passwd: not a regular file"}
	f := one(t, Diff(bl(map[string]baseline.FileEntry{}), live))
	if f.Kind != model.KindError || f.Category != "collector" || f.Severity != model.SevHigh || f.Subject != "/etc/passwd" || f.Detail != "could not read: not a regular file" {
		t.Fatalf("%+v", f)
	}
}

// The package layer must not hide a privilege gain on a file it vouches for.
func TestDiff_HashOnlyGainedSetuidIsPrivilege(t *testing.T) {
	p := "/usr/sbin/postfix"
	base := reg("1", 0o755, "")
	base.HashOnly = true
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{p: reg("1", 0o755|os.ModeSetuid, "")})))
	if f.Kind != model.KindAltered || f.Category != "privilege" || f.Severity != model.SevCritical || !strings.Contains(f.Detail, "setuid") {
		t.Fatalf("%+v", f)
	}
	live := reg("1", 0o755, "")
	live.Caps = "0100"
	f = one(t, Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{p: live})))
	if f.Category != "privilege" || f.Severity != model.SevCritical || !strings.Contains(f.Detail, "caps") {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_HashOnlyShippedSetuidIsNotAGain(t *testing.T) {
	p := "/usr/bin/su"
	base := reg("1", 0o755|os.ModeSetuid, "")
	base.HashOnly = true
	if fs := Diff(bl(map[string]baseline.FileEntry{p: base}), bl(map[string]baseline.FileEntry{p: reg("1", 0o755|os.ModeSetuid, "")})); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestDiff_PersistenceDirReplacedBySymlink(t *testing.T) {
	dir := baseline.FileEntry{Type: baseline.TypeDir, Mode: uint32(os.ModeDir | 0o755)}
	link := baseline.FileEntry{Type: baseline.TypeLink, Mode: uint32(os.ModeSymlink | 0o777), Link: "/tmp/x"}
	f := one(t, Diff(bl(map[string]baseline.FileEntry{"/etc/cron.d": dir}), bl(map[string]baseline.FileEntry{"/etc/cron.d": link})))
	if f.Category != "cron" || f.Severity != model.SevHigh || !strings.Contains(f.Detail, "type dir→symlink") {
		t.Fatalf("%+v", f)
	}
	// Any directory swapped for something else redirects everything below it.
	f = one(t, Diff(bl(map[string]baseline.FileEntry{"/etc/systemd": dir}), bl(map[string]baseline.FileEntry{"/etc/systemd": link})))
	if f.Category != "file" || f.Severity != model.SevHigh {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_PartialHashComparesSize(t *testing.T) {
	p := "/srv/big"
	b, l := reg("partial:1", 0o644, ""), reg("partial:1", 0o644, "")
	b.Size, l.Size = 2<<30, 3<<30
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: b}), bl(map[string]baseline.FileEntry{p: l})))
	if !strings.Contains(f.Detail, "size") {
		t.Fatalf("%+v", f)
	}
}

func TestDiff_SortedBySeverity(t *testing.T) {
	fs := Diff(bl(map[string]baseline.FileEntry{}), bl(map[string]baseline.FileEntry{
		"/srv/a":             reg("1", 0o644, ""),
		"/etc/ld.so.preload": reg("2", 0o644, "x"),
	}))
	if len(fs) != 2 || fs[0].Category != "preload" {
		t.Fatalf("%+v", fs)
	}
}

func TestDiff_Identical(t *testing.T) {
	b := bl(map[string]baseline.FileEntry{"/etc/crontab": reg("1", 0o644, "x")})
	if fs := Diff(b, b); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestDiff_UnifiedNoPhantomTrailingLine(t *testing.T) {
	p := "/etc/hosts"
	f := one(t, Diff(bl(map[string]baseline.FileEntry{p: reg("1", 0o644, "a\n")}), bl(map[string]baseline.FileEntry{p: reg("2", 0o644, "b\n")})))
	for _, line := range strings.Split(f.Diff, "\n") {
		if line == " " {
			t.Fatalf("phantom blank context line in diff:\n%s", f.Diff)
		}
	}
}
