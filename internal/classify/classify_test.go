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
		// a persistence directory is itself part of the persistence surface
		{"/etc/cron.d", "cron", true},
		{"/etc/systemd/system", "systemd-unit", true},
		{"/etc/systemd", "file", false},
		// homes are wherever passwd says: service accounts live outside /home
		{"/var/lib/mysql/.ssh/authorized_keys", "ssh-key", true},
		{"/var/www/.bashrc", "login-hook", true},
		{"/.ssh/authorized_keys", "ssh-key", true},
		{"/run/user/1000/systemd/user/x.service", "systemd-unit", true},
		{"/var/lib/systemd/linger/bob", "systemd-unit", true},
		{"/etc/cloud/cloud.cfg.d/99.cfg", "cloud-init", true},
		{"/var/lib/cloud/scripts/per-boot/x.sh", "cloud-init", true},
		{"/var/lib/cloud/instances/i-1/scripts/runcmd", "cloud-init", true},
		{"/etc/ld.so.cache", "resolver", false},
		// password hashes are never copied into a baseline
		{"/etc/passwd", "account-db", true},
		{"/etc/shadow", "account-db", false},
		{"/etc/gshadow", "account-db", false},
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

func TestMatch_DoubleStar(t *testing.T) {
	cases := []struct {
		pat, p string
		want   bool
	}{
		{"/etc/cron.d/**", "/etc/cron.d", true},
		{"/etc/cron.d/**", "/etc/cron.d/a/b", true},
		{"/etc/cron.d/**", "/etc/cron.daily", false},
		{"/etc/cron.d/**", "/etc", false},
		{"/**/.ssh/x", "/.ssh/x", false},
		{"/**/.ssh/x", "/a/b/.ssh/x", true},
	}
	for _, c := range cases {
		if got := Match(c.pat, c.p); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pat, c.p, got, c.want)
		}
	}
}
