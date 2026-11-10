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

func TestDiff_ErrEntriesSkipped(t *testing.T) {
	p := "/etc/secret"
	live := reg("", 0o600, "")
	live.Err = "permission denied"
	if fs := Diff(bl(map[string]baseline.FileEntry{p: reg("1", 0o600, "")}), bl(map[string]baseline.FileEntry{p: live})); len(fs) != 0 {
		t.Fatalf("%+v", fs)
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
