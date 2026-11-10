package collect

// Excluded paths (relative to the scanned root) are not walked at all.
// /dev is special-cased in Walk: only /dev/shm beneath it is walked.
var Excluded = []string{
	"/proc",
	"/sys",
	"/run/user",
	"/run/udev",
	"/run/systemd/journal",
	// Per-running-unit bookkeeping that comes and goes as services start
	// and stop (seen on a clean 24.04 rescan). Unit files are not loaded
	// from either; /run/systemd/{system,user} stay walked.
	"/run/systemd/units",
	"/run/systemd/propagate",
	"/var/log",
	"/var/cache",
	"/var/tmp/systemd-private-*",
	"/tmp/systemd-private-*",
	"/var/lib/apt/lists",
	"/var/lib/docker",     // container state: inspected separately
	"/var/lib/containerd", // container state: inspected separately
	"/var/lib/snapd",
	"/snap",
	"/var/lib/systemd",
	"/var/lib/dhcp",
	"/var/lib/cloud",
	"/var/lib/mysql",     // database files: inspected separately
	"/var/spool/postfix", // mail queue
	"/var/backups",
	"/lost+found",
}

// Ignored paths are walked but dropped from the snapshot: per-instance
// identity files that legitimately differ from the clean image.
var Ignored = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
	"/etc/hostname",
	"/etc/ssh/ssh_host_*",
	"/etc/netplan/**",
	"/etc/cloud/**",
	"/etc/ld.so.cache",
	"/etc/mtab",
	"/etc/adjtime",
	"/etc/.pwd.lock",
}
