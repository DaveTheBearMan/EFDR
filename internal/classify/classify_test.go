package classify

import (
	"testing"

	"xdr/internal/model"
)

func TestPath_Table(t *testing.T) {
	cases := []struct {
		path, cat string
		keep      bool
	}{
		{"/etc/ld.so.preload", "preload", true},
		{"/usr/lib/systemd/system-generators/x", "systemd-generator", true},
		{"/etc/systemd/system/evil.service", "systemd-unit", true},
		{"/home/bob/.config/systemd/user/a.timer", "systemd-unit", true},
		{"/root/.ssh/authorized_keys2", "ssh-key", true},
		{"/var/lib/dpkg/info/foo.postinst", "pkg-hook", true},
		{"/home/bob/.forward", "mail", true},
		{"/etc/cron.daily/x", "cron", true},
		{"/etc/pam.d/sshd", "pam", true},
		{"/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "pam", false},
		{"/usr/bin/ls", "system-binary", false},
		{"/srv/x", "file", false},
	}
	for _, c := range cases {
		got := Path(c.path)
		if got.Category != c.cat || got.KeepContent != c.keep {
			t.Errorf("Path(%q) = %+v, want %s keep=%v", c.path, got, c.cat, c.keep)
		}
	}
	if Path("/etc/ld.so.preload").Severity != model.SevCritical {
		t.Error("preload should be critical")
	}
}
