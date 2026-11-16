package install

import (
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// File is a file install writes: its path as the box sees it.
type File struct {
	Path    string
	Content []byte
	Mode    fs.FileMode
}

// Chooser is the shell script every launch point starts with: it runs the
// first copy whose sha256 equals the pinned hash, with the script's
// arguments, and exits 127 when none matches.
func Chooser(l Layout) string {
	var paths []string
	for _, c := range l.Copies {
		paths = append(paths, l.p(c))
	}
	return fmt.Sprintf(`for b in %s; do [ "$(sha256sum "$b" 2>/dev/null | cut -d" " -f1)" = "$(cat %s 2>/dev/null)" ] && exec "$b" "$@"; done; exit 127`,
		strings.Join(paths, " "), l.p(l.Pinned))
}

// shLaunch is a command line that runs the chooser with args.
func shLaunch(l Layout, args string) string {
	return fmt.Sprintf("/bin/sh -c '%s' xdr %s", Chooser(l), args)
}

// unitLaunch is shLaunch for a systemd ExecStart: $ is written $$.
func unitLaunch(l Layout, args string) string {
	return strings.ReplaceAll(shLaunch(l, args), "$", "$$")
}

func agentArgs(l Layout, withBase bool) string {
	if withBase {
		return "agent --config " + l.p(l.Config) + " --baseline " + l.p(l.Baseline)
	}
	return "agent --config " + l.p(l.Config)
}

// baseBackup is where the backup of the install's baseline goes.
func (l Layout) baseBackup() string { return l.Backup + "/baseline.json.gz" }

// hasBaseline reports whether the install has a baseline: it, or its
// backup, is on the box.
func (l Layout) hasBaseline() bool {
	if l.Baseline == "" {
		return false
	}
	for _, p := range []string{l.Baseline, l.baseBackup()} {
		if _, err := os.Lstat(l.p(p)); err == nil {
			return true
		}
	}
	return false
}

// Render is every file install writes besides the binary copies, the
// backup and the manifest: the units, the timer, the cron entry, the
// generator, the apt hook and the launcher script. The agent's unit passes
// the install's baseline when it has one.
func Render(l Layout) []File { return render(l, l.hasBaseline()) }

func render(l Layout, withBase bool) []File {
	unit := func(desc, exec, extra, wantedBy string) []byte {
		return []byte(fmt.Sprintf("[Unit]\nDescription=%s\nAfter=local-fs.target\n\n[Service]\n%sExecStart=%s\n\n[Install]\nWantedBy=%s\n", desc, extra, exec, wantedBy))
	}
	restart := "Restart=always\nRestartSec=1\n"
	return []File{
		{"/etc/systemd/system/xdr-agent.service", unit("XDR agent", unitLaunch(l, agentArgs(l, withBase)), restart, "multi-user.target"), 0o644},
		{"/etc/systemd/system/xdr-guard-a.service", unit("XDR guard A", unitLaunch(l, "guard --watch xdr-guard-b.service --every 5s"), restart, "multi-user.target"), 0o644},
		{"/etc/systemd/system/xdr-guard-b.service", unit("XDR guard B", unitLaunch(l, "guard --watch xdr-guard-a.service --every 5s"), restart, "multi-user.target"), 0o644},
		{"/etc/systemd/system/xdr-ensure.service", unit("XDR ensure", unitLaunch(l, "ensure"), "Type=oneshot\n", "multi-user.target"), 0o644},
		{"/etc/systemd/system/xdr-ensure.timer", []byte("[Unit]\nDescription=XDR ensure, every 30 s\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\nUnit=xdr-ensure.service\n\n[Install]\nWantedBy=timers.target\n"), 0o644},
		{"/etc/cron.d/xdr-ensure", []byte(fmt.Sprintf("SHELL=/bin/sh\n@reboot root %s\n* * * * * root %s\n", shLaunch(l, "ensure"), shLaunch(l, "ensure"))), 0o644},
		{"/usr/lib/systemd/system-generators/xdr-generator", []byte(`#!/bin/sh
# Puts the agent, the guards and the timer in the boot even if their links were removed.
mkdir -p "$1/multi-user.target.wants" "$1/timers.target.wants"
for u in xdr-agent.service xdr-guard-a.service xdr-guard-b.service; do
  ln -sf /etc/systemd/system/$u "$1/multi-user.target.wants/$u"
done
ln -sf /etc/systemd/system/xdr-ensure.timer "$1/timers.target.wants/xdr-ensure.timer"
`), 0o755},
		{"/etc/apt/apt.conf.d/99xdr", []byte(fmt.Sprintf("DPkg::Post-Invoke { \"%s ensure || true\"; };\n", l.p("/usr/lib/xdr/launch"))), 0o644},
		{"/usr/lib/xdr/launch", []byte("#!/bin/sh\n" + Chooser(l) + "\n"), 0o755},
	}
}
