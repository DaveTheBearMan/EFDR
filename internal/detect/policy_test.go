package detect

import (
	"net/netip"
	"path"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/pathenc"
	"xdr/internal/proc"
)

const (
	ns      = "net:[1]"
	selfPID = 77
)

var dockerID = strings.Repeat("0123456789abcdef", 4)

func pfx(s string) config.Net    { return config.Net{Prefix: netip.MustParsePrefix(s)} }
func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// hashes is what the stub Hash reports per exe; the baseline below agrees
// with it for everything but /usr/bin/changed.
var hashes = map[string]string{
	"/usr/bin/bash": "aa", "/usr/bin/dash": "bb", "/usr/bin/curl": "cc", "/usr/sbin/apache2": "dd",
	"/usr/bin/changed": "new", "/usr/lib/systemd/systemd": "ee",
}

func pol() *Policy {
	base := &baseline.Baseline{Files: map[string]baseline.FileEntry{}}
	for exe, sum := range hashes {
		base.Files[pathenc.Encode(exe)] = baseline.FileEntry{SHA256: sum}
	}
	base.Files[pathenc.Encode("/usr/bin/changed")] = baseline.FileEntry{SHA256: "old"}
	base.Files[pathenc.Encode("/usr/bin/unhashed")] = baseline.FileEntry{}
	return &Policy{
		Cfg: &config.Config{
			Host:      "web01",
			Jump:      []config.Net{pfx("192.0.2.7/32")},
			Peers:     []config.Net{pfx("192.0.2.4/32"), pfx("192.0.2.6/32")},
			SSHPort:   22,
			XDRPorts:  []uint16{7443},
			Scored:    []config.Port{{Proto: "tcp", Port: 80}, {Proto: "tcp", Port: 22}},
			AllowOut:  []config.Dest{{To: pfx("192.0.2.6/32"), Proto: "tcp", Port: 3306}},
			GuardExes: []string{"/usr/sbin/apache2", "/usr/bin/containerd-shim-runc-v2"},
			Listeners: []config.Listener{{Proto: "udp", Port: 68, Exe: "/usr/lib/systemd/systemd-networkd"}},
			DHCP:      true,
		},
		Base:  base,
		Gray:  map[uint32]bool{2001: true},
		Self:  selfPID,
		Local: func(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.5") },
		Hash:  func(pr *proc.Proc) string { return hashes[pr.Exe] },
	}
}

// mk is a process in the host namespace holding the given sockets.
func mk(pid, ppid int, exe string, fds map[int]uint64) *proc.Proc {
	if fds == nil {
		fds = map[int]uint64{}
	}
	return &proc.Proc{PID: pid, PPID: ppid, Start: uint64(1000 + pid), Comm: path.Base(exe), Exe: exe, NetNS: ns, FDs: fds}
}

func family(a netip.AddrPort) int {
	if a.Addr().Is4() {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

func lsn(inode uint64, proto, local string) proc.Sock {
	l := ap(local)
	return proc.Sock{Inode: inode, Family: family(l), Proto: proto, Local: l, Listen: true}
}

func conn(inode uint64, proto, local, remote string) proc.Sock {
	l := ap(local)
	return proc.Sock{Inode: inode, Family: family(l), Proto: proto, Local: l, Remote: ap(remote)}
}

type procs []*proc.Proc

func snap(ps procs, socks ...proc.Sock) *proc.Snapshot {
	s := &proc.Snapshot{Procs: map[int]*proc.Proc{}, Socks: map[string]map[uint64]proc.Sock{ns: {}}}
	for _, p := range ps {
		s.Procs[p.PID] = p
	}
	for _, k := range socks {
		s.Socks[ns][k.Inode] = k
	}
	return s
}

func TestClass(t *testing.T) {
	for exe, want := range map[string]string{
		"/usr/bin/bash": "shell", "/usr/bin/dash": "shell", "/bin/busybox": "shell",
		"/usr/bin/python3.12": "interp", "/usr/bin/perl": "interp", "/usr/bin/php8.3": "interp", "/usr/bin/node": "interp", "/usr/bin/gawk": "interp",
		"/usr/bin/nc.openbsd": "nettool", "/usr/bin/socat": "nettool", "/usr/bin/openssl": "nettool",
		"/usr/sbin/apache2": "", "/usr/bin/nodejs-thing": "", "/usr/bin/shred": "", "": "",
	} {
		if got := Class(&proc.Proc{Exe: exe}); got != want {
			t.Errorf("Class(%q) = %q, want %q", exe, got, want)
		}
	}
	if got := Class(&proc.Proc{Comm: "bash"}); got != "shell" {
		t.Errorf("no exe, comm bash: %q", got)
	}
	if got := Class(&proc.Proc{Comm: "bash", Exe: "/usr/sbin/apache2"}); got != "" {
		t.Errorf("exe wins over comm: %q", got)
	}
}

func TestAllowedOut_V4MappedAndOwnAddress(t *testing.T) {
	p := pol()
	for _, c := range []struct {
		dst, proto string
		want       bool
	}{
		{"[::ffff:192.0.2.4]:7443", "tcp", true}, // a peer, v4-mapped
		{"192.0.2.7:7443", "tcp", true},          // the jump box
		{"192.0.2.5:3306", "tcp", true},          // this host
		{"127.0.0.1:53", "udp", true},
		{"[::1]:8080", "tcp", true},
		{"224.0.0.251:5353", "udp", true},
		{"255.255.255.255:67", "udp", true},
		{"192.0.2.6:3306", "tcp", true}, // allow_out
		{"192.0.2.1:67", "udp", true},   // dhcp
		{"203.0.113.9:443", "tcp", false},
		{"192.0.2.4:22", "tcp", false},   // a peer, but not an xdr port
		{"192.0.2.4:7443", "udp", false}, // xdr is tcp
		{"192.0.2.6:3306", "udp", false},
		{"192.0.2.6:3307", "tcp", false},
		{"192.0.2.1:67", "tcp", false},
		{"192.0.2.1:53", "udp", false}, // the resolver is for the stub alone
		{"[2001:db8::1]:443", "tcp", false},
	} {
		if got := p.AllowedOut(ap(c.dst), c.proto); got != c.want {
			t.Errorf("AllowedOut(%s, %s) = %v", c.dst, c.proto, got)
		}
	}
	p.Cfg.DHCP = false
	if p.AllowedOut(ap("192.0.2.1:67"), "udp") {
		t.Error("dhcp off: udp/67 still allowed")
	}
}

func TestBaseline_PathAndHash(t *testing.T) {
	p := pol()
	for name, c := range map[string]struct {
		pr   proc.Proc
		want bool
	}{
		"same path and hash": {proc.Proc{Exe: "/usr/bin/bash"}, true},
		"other hash":         {proc.Proc{Exe: "/usr/bin/changed"}, false},
		"not in baseline":    {proc.Proc{Exe: "/tmp/x"}, false},
		"no hash recorded":   {proc.Proc{Exe: "/usr/bin/unhashed"}, false},
		"container":          {proc.Proc{Exe: "/usr/bin/bash", Cgroup: "/system.slice/docker-" + dockerID + ".scope"}, false},
		"deleted":            {proc.Proc{Exe: "/usr/bin/bash", ExeDeleted: true}, false},
		"no exe":             {proc.Proc{}, false},
	} {
		if got := p.Baseline(&c.pr); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	p.Base = nil
	if p.Baseline(&proc.Proc{Exe: "/usr/bin/bash"}) {
		t.Error("nil baseline: true")
	}
}

func TestGuardedAndGray(t *testing.T) {
	p := pol()
	s := snap(procs{
		mk(1, 0, "/usr/lib/systemd/systemd", nil),
		mk(900, 1, "/usr/sbin/apache2", nil),
		mk(910, 1, "/usr/sbin/nginx", map[int]uint64{6: 80}),
		mk(920, 1, "/usr/sbin/mysqld", map[int]uint64{6: 3306}),
		mk(930, 1, "/tmp/x", map[int]uint64{3: 81}),
		{PID: 50, PPID: 1, UID: 2001, NetNS: ns},
		{PID: 51, PPID: 50, UID: 0, NetNS: ns},
		{PID: 52, PPID: 1, UID: 1000, NetNS: ns},
	}, lsn(80, "tcp", "0.0.0.0:80"), lsn(3306, "tcp", "0.0.0.0:3306"), conn(81, "tcp", "192.0.2.5:80", "203.0.113.9:5000"))
	for pid, want := range map[int]bool{900: true, 910: true, 920: false, 930: false, 1: false} {
		if got := p.Guarded(s, s.Procs[pid]); got != want {
			t.Errorf("Guarded(%d) = %v", pid, got)
		}
	}
	for pid, want := range map[int]bool{50: true, 51: true, 52: false} {
		if got := p.IsGray(s, s.Procs[pid]); got != want {
			t.Errorf("IsGray(%d) = %v", pid, got)
		}
	}
}
