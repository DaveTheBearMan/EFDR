package rules

import (
	"errors"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"strings"

	"xdr/internal/baseline"
	"xdr/internal/proc"
)

// Guard is what no rule may hit: the base image, the scored services and
// the addresses the fleet itself depends on.
type Guard struct {
	Baseline  func(sha256 string) bool  // a hash of the base image
	GuardExes []string                  // scored-service binaries
	Protect   []netip.Prefix            // jump box, peers, resolver, scorer allows
	StockCron func(command string) bool // a command a base-image crontab runs
}

// maxPath caps the paths and commands a rule names.
const maxPath = 512

// launchers start sessions, jobs and containers: a shell under one of
// them is how people and stock jobs work, so no parent rule may name it.
var launchers = []string{"systemd", "init", "sshd", "sshd-session", "cron", "atd", "login", "sudo", "su", "tmux", "screen"}

var unitName = regexp.MustCompile(`^[A-Za-z0-9:_.@-]{1,200}\.(service|timer|socket)$`)

func launcher(exe string) bool {
	name := path.Base(exe)
	return slices.Contains(launchers, name) || strings.HasPrefix(name, "containerd-shim") || proc.Class(exe, "") != ""
}

func absPath(p string) error {
	switch {
	case len(p) > maxPath:
		return errors.New("path too long")
	case !path.IsAbs(p):
		return errors.New("not an absolute path")
	}
	return nil
}

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Validate reports why r may not be enforced, or nil.
func (g Guard) Validate(r Rule) error {
	switch r.Kind {
	case "hash":
		if !hexSum(r.SHA256) {
			return errors.New("bad hash")
		}
		if g.Baseline != nil && g.Baseline(r.SHA256) {
			return errors.New("baseline hash")
		}
		if slices.Contains(g.GuardExes, r.Exe) {
			return errors.New("guarded exe")
		}
	case "remote":
		a := r.Addr.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
			a.IsLinkLocalUnicast() || a.IsInterfaceLocalMulticast() || a == broadcast {
			return errors.New("not a unicast address")
		}
		if r.Port == 0 {
			return errors.New("no port")
		}
		if r.Proto != "tcp" && r.Proto != "udp" {
			return errors.New("bad proto")
		}
		for _, p := range g.Protect {
			if p.Contains(a) {
				return errors.New("protected address")
			}
		}
	case "parent":
		if err := absPath(r.ParentExe); err != nil {
			return err
		}
		if err := absPath(r.Exe); err != nil {
			return err
		}
		if proc.Class(r.Exe, "") == "" {
			return errors.New("child is not a shell, interpreter or net tool")
		}
		if launcher(r.ParentExe) {
			return errors.New("launcher parent")
		}
	case "unit":
		if !unitName.MatchString(r.Unit) {
			return errors.New("bad unit name")
		}
		if !hexSum(r.SHA256) {
			return errors.New("bad hash")
		}
		if g.Baseline != nil && g.Baseline(r.SHA256) {
			return errors.New("baseline hash")
		}
	case "cron":
		switch {
		case strings.TrimSpace(r.Command) == "":
			return errors.New("no command")
		case len(r.Command) > maxPath:
			return errors.New("command too long")
		case g.StockCron != nil && g.StockCron(r.Command):
			return errors.New("stock cron")
		}
	default:
		return errors.New("unknown kind")
	}
	return nil
}

func hexSum(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// BaselineHashes is the set of file hashes in b.
func BaselineHashes(b *baseline.Baseline) func(string) bool {
	set := map[string]bool{}
	if b != nil {
		for _, e := range b.Files {
			if e.SHA256 != "" {
				set[e.SHA256] = true
			}
		}
	}
	return func(s string) bool { return set[s] }
}
