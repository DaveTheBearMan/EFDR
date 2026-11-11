package collect

// Skipped paths (relative to the scanned root) are kernel views, not
// files: never entered, never recorded. The same filesystems mounted
// anywhere else are caught by type (see pseudoFS).
var Skipped = []string{
	"/proc",
	"/sys",
}

// Sealed directories are recorded but not entered: container storage is
// root-only (0710) and inspected by its own tooling.
var Sealed = []string{
	"/var/lib/docker",
	"/var/lib/containerd",
}

// Volatile trees churn on a healthy box, so they are not inventoried file
// by file. They are still walked: a setuid/setgid or capability-carrying
// file, or a path that classifies as a persistence location, is recorded
// wherever it sits.
var Volatile = []string{
	"/run/user",
	"/run/udev",
	"/run/systemd/journal",
	// Per-running-unit bookkeeping that comes and goes as services start
	// and stop (seen on a clean 24.04 rescan). Unit files are not loaded
	// from either; /run/systemd/{system,user} are inventoried in full.
	"/run/systemd/units",
	"/run/systemd/propagate",
	"/var/log",
	"/var/cache",
	"/var/tmp/systemd-private-*",
	"/tmp/systemd-private-*",
	"/var/lib/apt/lists",
	"/var/lib/snapd",
	"/snap",
	"/var/lib/systemd",
	"/var/lib/dhcp",
	"/var/lib/cloud",
	"/var/lib/mysql",     // database files: inspected separately
	"/var/spool/postfix", // mail queue
	"/var/lib/samba",     // tdb state; usershares are kept by class
	"/var/backups",
	"/lost+found",
}

// Ignored names are per-instance identity files that legitimately differ
// from the clean image. Only a plain, unprivileged regular file is dropped;
// a symlink, special file or setuid file under one of these names is
// recorded like anything else.
var Ignored = []string{
	"/etc/machine-id",
	"/var/lib/dbus/machine-id",
	"/etc/hostname",
	"/etc/ssh/ssh_host_*",
	"/etc/netplan/**",
	"/etc/mtab",
	"/etc/adjtime",
	"/etc/.pwd.lock",
}
