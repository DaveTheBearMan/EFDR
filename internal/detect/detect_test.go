package detect

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"xdr/internal/incident"
	"xdr/internal/config"
	"xdr/internal/model"
	"xdr/internal/proc"
	"xdr/internal/sensor"
)

// kinds lists detections as "kind:pid", in order.
func kinds(ds []Detection) []string {
	out := []string{}
	for _, d := range ds {
		out = append(out, fmt.Sprintf("%s:%d", d.Kind, d.PID))
	}
	return out
}

func want(t *testing.T, ds []Detection, kindPids ...string) {
	t.Helper()
	if kindPids == nil {
		kindPids = []string{}
	}
	if got := kinds(ds); !reflect.DeepEqual(got, kindPids) {
		t.Fatalf("got %v, want %v\n%+v", got, kindPids, ds)
	}
}

func only(ds []Detection, kind string) (out []Detection) {
	for _, d := range ds {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	return out
}

var systemd = mk(1, 0, "/usr/lib/systemd/systemd", nil)

func TestSweep_RevshellStdio(t *testing.T) {
	stdio := map[int]uint64{0: 500, 1: 500, 2: 500}
	c2 := conn(500, "tcp", "192.0.2.5:40000", "203.0.113.9:4444")
	ds := only(Sweep(snap(procs{systemd, mk(10, 1, "/usr/bin/bash", stdio)}, c2), pol()), "revshell-stdio")
	want(t, ds, "revshell-stdio:10")
	d := ds[0]
	if d.Severity != model.SevCritical || d.Start != 1010 || d.NoKill || d.Detail == "" ||
		!reflect.DeepEqual(d.Remote, &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"}) {
		t.Fatalf("%+v remote %+v", d, d.Remote)
	}
	for name, c := range map[string]struct {
		pr   *proc.Proc
		sock proc.Sock
		hit  bool
	}{
		"python on stdout only": {mk(10, 1, "/usr/bin/python3.12", map[int]uint64{1: 500}), c2, true},
		"bind shell":            {mk(10, 1, "/usr/bin/dash", stdio), conn(500, "tcp", "192.0.2.5:4444", "203.0.113.9:50000"), true},
		"v6":                    {mk(10, 1, "/usr/bin/bash", stdio), conn(500, "tcp", "[2001:db8::5]:40000", "[2001:db8::9]:4444"), true},
		"bash on a pty":         {mk(10, 1, "/usr/bin/bash", nil), c2, false},
		"socket on fd 3":        {mk(10, 1, "/usr/bin/bash", map[int]uint64{3: 500}), c2, false},
		"unix socket":           {mk(10, 1, "/usr/bin/bash", stdio), proc.Sock{Inode: 500, Family: unix.AF_UNIX, Proto: "unix"}, false},
		"not a shell":           {mk(10, 1, "/usr/sbin/inetd-thing", stdio), c2, false},
		"fastcgi listen socket": {mk(10, 1, "/usr/sbin/php-fpm8.3", map[int]uint64{0: 500}), lsn(500, "tcp", "127.0.0.1:9000"), false},
		"socket in other netns": {&proc.Proc{PID: 10, PPID: 1, Exe: "/usr/bin/bash", NetNS: "net:[2]", FDs: stdio}, c2, false},
	} {
		got := only(Sweep(snap(procs{systemd, c.pr}, c.sock), pol()), "revshell-stdio")
		if (len(got) == 1) != c.hit {
			t.Errorf("%s: %v", name, kinds(got))
		}
	}
}

// web is apache with a worker, both holding the scored listener.
func web() procs {
	return procs{
		systemd,
		mk(900, 1, "/usr/sbin/apache2", map[int]uint64{4: 80}),
		mk(901, 900, "/usr/sbin/apache2", map[int]uint64{4: 80}),
	}
}

func TestSweep_ServiceShell(t *testing.T) {
	http := lsn(80, "tcp", "0.0.0.0:80")
	ds := Sweep(snap(append(web(), mk(950, 901, "/usr/bin/dash", nil), mk(951, 950, "/usr/bin/id", nil), mk(952, 901, "/usr/bin/nc.openbsd", nil)), http), pol())
	want(t, ds, "service-shell:950", "service-shell:952")
	if ds[0].Severity != model.SevHigh || ds[0].Start != 1950 || !strings.Contains(ds[0].Detail, "apache2") {
		t.Fatalf("%+v", ds[0])
	}
	// A container runtime shim is guarded but listens on nothing.
	want(t, Sweep(snap(procs{systemd, mk(800, 1, "/usr/bin/containerd-shim-runc-v2", nil), mk(801, 800, "/usr/bin/dash", nil)}), pol()))
	// sshd listens on a scored port; a login shell is not a service shell.
	ssh := lsn(22, "tcp", "0.0.0.0:22")
	want(t, Sweep(snap(procs{systemd,
		mk(700, 1, "/usr/sbin/sshd", map[int]uint64{3: 22}),
		mk(701, 700, "/usr/sbin/sshd", nil),
		mk(702, 701, "/usr/bin/bash", nil)}, ssh), pol()))
	// Socket activation: init holds the scored listener, and everything
	// on the box descends from init.
	want(t, Sweep(snap(procs{
		mk(1, 0, "/usr/lib/systemd/systemd", map[int]uint64{40: 22}),
		mk(600, 1, "/usr/sbin/cron", nil),
		mk(601, 600, "/usr/bin/dash", nil)}, ssh), pol()))
	// An interpreter under the service is the service's own business.
	want(t, Sweep(snap(append(web(), mk(950, 901, "/usr/bin/python3.12", nil)), http), pol()))
}

func TestSweep_Egress(t *testing.T) {
	http := lsn(80, "tcp", "0.0.0.0:80")
	synsent := conn(500, "tcp", "192.0.2.5:40000", "203.0.113.9:443")
	synsent.SynSent = true
	for name, c := range map[string]struct {
		sock proc.Sock
		want []string
	}{
		"syn sent to a stranger":   {synsent, []string{"egress:10"}},
		"connected to a stranger":  {conn(500, "tcp", "192.0.2.5:40000", "203.0.113.9:443"), []string{"egress:10"}},
		"accepted on the listener": {conn(500, "tcp", "192.0.2.5:80", "203.0.113.9:51000"), nil},
		"connected to a peer":      {conn(500, "tcp", "192.0.2.5:40000", "192.0.2.4:7443"), nil},
		"allow_out":                {conn(500, "tcp", "192.0.2.5:40000", "192.0.2.6:3306"), nil},
		"loopback":                 {conn(500, "tcp", "127.0.0.1:40000", "127.0.0.1:3306"), nil},
		"udp connected, dns":       {conn(500, "udp", "192.0.2.5:40000", "203.0.113.53:53"), []string{"dns:10"}},
		"tcp to the resolver":      {conn(500, "tcp", "192.0.2.5:40000", "192.0.2.1:53"), []string{"dns:10"}},
		"dns over tls":             {conn(500, "tcp", "192.0.2.5:40000", "203.0.113.53:853"), []string{"dns:10"}},
		"udp connected, other":     {conn(500, "udp", "192.0.2.5:40000", "203.0.113.9:9999"), []string{"egress:10"}},
		"udp bound, high port":     {lsn(500, "udp", "0.0.0.0:40000"), nil},
		"v4-mapped peer":           {proc.Sock{Inode: 500, Family: unix.AF_INET6, Proto: "tcp", Local: ap("192.0.2.5:40000"), Remote: ap("192.0.2.4:7443")}, nil},
		"closed socket, no remote": {proc.Sock{Inode: 500, Family: unix.AF_INET, Proto: "tcp", Local: ap("0.0.0.0:0"), Remote: ap("0.0.0.0:0")}, nil},
	} {
		ds := Sweep(snap(append(web(), mk(10, 1, "/usr/bin/curl", map[int]uint64{5: 500, 6: 500})), http, c.sock), pol())
		if c.want == nil {
			c.want = []string{}
		}
		if got := kinds(ds); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v", name, got)
			continue
		}
		if len(ds) == 1 && (ds[0].Severity != model.SevHigh || ds[0].Remote == nil || ds[0].Remote.Port != c.sock.Remote.Port() || ds[0].Remote.Proto != c.sock.Proto) {
			t.Errorf("%s: %+v %+v", name, ds[0], ds[0].Remote)
		}
	}
}

func TestSweep_RawSock(t *testing.T) {
	packet := proc.Sock{Inode: 500, Family: unix.AF_PACKET, Proto: "packet"}
	raw := proc.Sock{Inode: 501, Family: unix.AF_INET, Proto: "raw", Local: ap("0.0.0.0:1"), Listen: true}
	ds := Sweep(snap(procs{systemd,
		mk(10, 1, "/tmp/sniff", map[int]uint64{3: 500}),
		mk(11, 1, "/tmp/icmpsh", map[int]uint64{3: 501}),
		mk(12, 1, "/tmp/both", map[int]uint64{3: 500, 4: 501}),
		mk(13, 1, "/usr/bin/curl", nil)}, packet, raw), pol())
	want(t, ds, "rawsock:10", "rawsock:11", "rawsock:12")
	if ds[0].Severity != model.SevHigh || ds[0].NoKill {
		t.Fatalf("%+v", ds[0])
	}
}

func TestSweep_Listener(t *testing.T) {
	networkd := "/usr/lib/systemd/systemd-networkd"
	for name, c := range map[string]struct {
		ps   procs
		sock proc.Sock
		want []string
	}{
		"unknown tcp":                  {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "tcp", "0.0.0.0:4444"), []string{"listener:10"}},
		"unknown tcp v6":               {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "tcp", "[::]:4444"), []string{"listener:10"}},
		"scored":                       {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "tcp", "0.0.0.0:80"), nil},
		"scored port, other proto":     {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "udp", "0.0.0.0:80"), []string{"listener:10"}},
		"listed":                       {procs{mk(10, 1, networkd, map[int]uint64{3: 500})}, lsn(500, "udp", "192.0.2.5:68"), nil},
		"listed port, other exe":       {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "udp", "192.0.2.5:68"), []string{"listener:10"}},
		"listed, shared with a helper": {procs{mk(10, 1, networkd, map[int]uint64{3: 500}), mk(11, 10, "/usr/bin/helper", map[int]uint64{3: 500})}, lsn(500, "udp", "192.0.2.5:68"), nil},
		"docker-proxy":                 {procs{mk(10, 1, "/usr/bin/docker-proxy", map[int]uint64{3: 500})}, lsn(500, "tcp", "0.0.0.0:8080"), nil},
		"udp high port":                {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "udp", "0.0.0.0:40000"), nil},
		"udp low port":                 {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, "udp", "0.0.0.0:5353"), []string{"listener:10"}},
		"connected udp":                {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, conn(500, "udp", "127.0.0.1:5353", "127.0.0.1:9"), nil},
		"forked holders":               {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500}), mk(11, 10, "/tmp/x", map[int]uint64{3: 500}), mk(12, 11, "/tmp/x", map[int]uint64{7: 500})}, lsn(500, "tcp", "0.0.0.0:4444"), []string{"listener:10"}},
		"two fds, one socket":          {procs{mk(10, 1, "/tmp/x", map[int]uint64{3: 500, 4: 500})}, lsn(500, "tcp", "0.0.0.0:4444"), []string{"listener:10"}},
	} {
		ds := Sweep(snap(append(procs{systemd}, c.ps...), c.sock), pol())
		if c.want == nil {
			c.want = []string{}
		}
		if got := kinds(ds); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v", name, got)
		} else if len(ds) == 1 && (ds[0].Severity != model.SevHigh || ds[0].NoKill || !strings.Contains(ds[0].Detail, fmt.Sprint(c.sock.Local.Port()))) {
			t.Errorf("%s: %+v", name, ds[0])
		}
	}
	for _, local := range []string{"127.0.0.1:9000", "[::1]:9000", "127.0.0.53:53"} {
		proto := "tcp"
		ds := Sweep(snap(procs{systemd, mk(10, 1, "/tmp/x", map[int]uint64{3: 500})}, lsn(500, proto, local)), pol())
		want(t, ds, "listener:10")
		if ds[0].Severity != model.SevLow || !ds[0].NoKill {
			t.Errorf("%s: %+v", local, ds[0])
		}
	}
}

func TestSweep_IgnoresSelfAndKernelThreads(t *testing.T) {
	fds := map[int]uint64{0: 500, 3: 501, 4: 502}
	socks := []proc.Sock{
		conn(500, "tcp", "192.0.2.5:40000", "203.0.113.9:4444"),
		lsn(501, "tcp", "0.0.0.0:4444"),
		{Inode: 502, Family: unix.AF_PACKET, Proto: "packet"},
	}
	kthread := mk(30, 2, "", fds)
	kthread.Kernel, kthread.Comm = true, "bash"
	want(t, Sweep(snap(procs{systemd, mk(selfPID, 1, "/usr/bin/bash", fds), kthread}, socks...), pol()))
	// The same sockets on anything else are reported.
	want(t, Sweep(snap(procs{systemd, mk(31, 1, "/usr/bin/bash", fds)}, socks...), pol()),
		"revshell-stdio:31", "egress:31", "rawsock:31", "listener:31")
}

func TestEvent_ConnectDenied(t *testing.T) {
	s := snap(procs{systemd, mk(50, 1, "/usr/bin/curl", nil)})
	ds := Event(sensor.Event{Kind: sensor.Connect, PID: 50, Dst: ap("203.0.113.9:443"), Proto: "tcp"}, s, pol())
	want(t, ds, "egress:50")
	if ds[0].Start != 1050 || ds[0].Severity != model.SevHigh || !reflect.DeepEqual(ds[0].Remote, &incident.Endpoint{Addr: "203.0.113.9", Port: 443, Proto: "tcp"}) {
		t.Fatalf("%+v %+v", ds[0], ds[0].Remote)
	}
	// The process is already gone: still worth a line.
	ds = Event(sensor.Event{Kind: sensor.Connect, PID: 60, Dst: ap("203.0.113.9:443"), Proto: "tcp"}, s, pol())
	want(t, ds, "egress:60")
	if ds[0].Start != 0 || !strings.HasSuffix(ds[0].Detail, " (exited)") {
		t.Fatalf("%+v", ds[0])
	}
}

func TestEvent_ConnectAllowed(t *testing.T) {
	kthread := mk(30, 2, "", nil)
	kthread.Kernel = true
	s := snap(procs{systemd, mk(50, 1, "/usr/bin/curl", nil), kthread})
	for name, ev := range map[string]sensor.Event{
		"peer":          {Kind: sensor.Connect, PID: 50, Dst: ap("192.0.2.4:7443"), Proto: "tcp"},
		"loopback":      {Kind: sensor.Connect, PID: 50, Dst: ap("127.0.0.1:53"), Proto: "udp"},
		"self":          {Kind: sensor.Connect, PID: selfPID, Dst: ap("203.0.113.9:443"), Proto: "tcp"},
		"kernel thread": {Kind: sensor.Connect, PID: 30, Dst: ap("203.0.113.9:2049"), Proto: "tcp"},
		"inet socket":   {Kind: sensor.Socket, PID: 50, Family: unix.AF_INET, SockType: unix.SOCK_STREAM},
		"plain exec":    {Kind: sensor.Exec, PID: 50, Filename: "/usr/bin/curl"},
	} {
		if ds := Event(ev, s, pol()); len(ds) != 0 {
			t.Errorf("%s: %v", name, kinds(ds))
		}
	}
}

func TestEvent_SendToPort53IsDNS(t *testing.T) {
	s := snap(procs{systemd, mk(50, 1, "/tmp/dnscat", nil)})
	ds := Event(sensor.Event{Kind: sensor.Send, PID: 50, Dst: ap("203.0.113.53:53"), Proto: "udp"}, s, pol())
	want(t, ds, "dns:50")
	if ds[0].Remote.Proto != "udp" || ds[0].Remote.Port != 53 {
		t.Fatalf("%+v", ds[0].Remote)
	}
	want(t, Event(sensor.Event{Kind: sensor.Send, PID: 50, Dst: ap("203.0.113.9:9999"), Proto: "udp"}, s, pol()), "egress:50")
}

func TestEvent_RawSocket(t *testing.T) {
	s := snap(procs{systemd, mk(50, 1, "/tmp/x", nil)})
	for name, ev := range map[string]sensor.Event{
		"packet":  {Kind: sensor.Socket, PID: 50, Family: unix.AF_PACKET, SockType: unix.SOCK_DGRAM},
		"raw":     {Kind: sensor.Socket, PID: 50, Family: unix.AF_INET, SockType: unix.SOCK_RAW},
		"raw6":    {Kind: sensor.Socket, PID: 50, Family: unix.AF_INET6, SockType: unix.SOCK_RAW},
		"flagged": {Kind: sensor.Socket, PID: 50, Family: unix.AF_INET, SockType: unix.SOCK_RAW | unix.SOCK_CLOEXEC},
	} {
		if ds := Event(ev, s, pol()); !reflect.DeepEqual(kinds(ds), []string{"rawsock:50"}) {
			t.Errorf("%s: %v", name, kinds(ds))
		}
	}
	// A raw netlink or unix socket is nothing of the kind.
	if ds := Event(sensor.Event{Kind: sensor.Socket, PID: 50, Family: unix.AF_NETLINK, SockType: unix.SOCK_RAW}, s, pol()); len(ds) != 0 {
		t.Errorf("netlink: %v", kinds(ds))
	}
}

func TestEvent_ExecShellThatExecedOn(t *testing.T) {
	http := lsn(80, "tcp", "0.0.0.0:80")
	s := snap(append(web(), mk(950, 901, "/usr/bin/sleep", nil)), http)
	want(t, Sweep(s, pol())) // the sweep sees only sleep
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 950, PPID: 901, Comm: "sh", Filename: "/bin/sh"}, s, pol())
	want(t, ds, "service-shell:950")
	if ds[0].Start != 1950 || strings.HasSuffix(ds[0].Detail, "(exited)") {
		t.Fatalf("%+v", ds[0])
	}
	// The same exec under a login is nothing.
	s = snap(procs{systemd, mk(700, 1, "/usr/sbin/sshd", map[int]uint64{3: 22}), mk(950, 700, "/usr/bin/sleep", nil)}, lsn(22, "tcp", "0.0.0.0:22"))
	want(t, Event(sensor.Event{Kind: sensor.Exec, PID: 950, PPID: 700, Filename: "/bin/sh"}, s, pol()))
}

func TestEvent_ExecOfExitedServiceShell(t *testing.T) {
	s := snap(web(), lsn(80, "tcp", "0.0.0.0:80"))
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 950, PPID: 901, Comm: "sh", Filename: "/bin/sh"}, s, pol())
	want(t, ds, "service-shell:950")
	if ds[0].Start != 0 || !strings.HasSuffix(ds[0].Detail, " (exited)") {
		t.Fatalf("%+v", ds[0])
	}
	// No filename: the comm decides.
	want(t, Event(sensor.Event{Kind: sensor.Exec, PID: 950, PPID: 901, Comm: "nc"}, s, pol()), "service-shell:950")
	// Parent unknown or not a service: nothing to judge by.
	want(t, Event(sensor.Event{Kind: sensor.Exec, PID: 950, Comm: "sh", Filename: "/bin/sh"}, s, pol()))
	want(t, Event(sensor.Event{Kind: sensor.Exec, PID: 950, PPID: 1, Comm: "sh", Filename: "/bin/sh"}, s, pol()))
}

func TestEvent_ExecShellOnSocket(t *testing.T) {
	s := snap(procs{systemd, mk(10, 1, "/usr/bin/sleep", map[int]uint64{0: 500})}, conn(500, "tcp", "192.0.2.5:40000", "203.0.113.9:4444"))
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 10, PPID: 1, Filename: "/usr/bin/bash"}, s, pol())
	want(t, ds, "revshell-stdio:10")
}

// A packet or raw socket held by a listed, unmodified binary (networkd's
// DHCP client) is known; the same path with other content is not.
func TestRawSock_KnownHolder(t *testing.T) {
	p := pol()
	p.Cfg.Listeners = append(p.Cfg.Listeners,
		config.Listener{Proto: "packet", Exe: "/usr/lib/systemd/systemd"},
		config.Listener{Proto: "packet", Exe: "/usr/bin/changed"})
	packet := proc.Sock{Inode: 500, Family: unix.AF_PACKET, Proto: "packet"}
	raw := proc.Sock{Inode: 501, Family: unix.AF_INET, Proto: "raw", Local: ap("0.0.0.0:1"), Listen: true}
	s := snap(procs{systemd,
		mk(10, 1, "/usr/lib/systemd/systemd", map[int]uint64{3: 500}),
		mk(11, 1, "/usr/bin/changed", map[int]uint64{3: 500}),
		mk(12, 1, "/usr/lib/systemd/systemd", map[int]uint64{3: 501})}, packet, raw)
	want(t, Sweep(s, p), "rawsock:11", "rawsock:12")
	if ds := Event(sensor.Event{Kind: sensor.Socket, PID: 10, Family: unix.AF_PACKET, SockType: unix.SOCK_RAW}, s, p); len(ds) != 0 {
		t.Fatalf("event: %v", kinds(ds))
	}
	want(t, Event(sensor.Event{Kind: sensor.Socket, PID: 11, Family: unix.AF_PACKET, SockType: unix.SOCK_RAW}, s, p), "rawsock:11")
}
