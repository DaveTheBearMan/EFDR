package proc

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"xdr/internal/testfs"
)

const (
	tcpHead = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tcpTail = " 00000000:00000000 00:00000000 00000000     0        0 "
	tcpEnd  = " 1 0000000000000000 100 0 0 10 0\n"
)

func line(local, remote, state, inode string) string {
	return "   0: " + local + " " + remote + " " + state + tcpTail + inode + tcpEnd
}

// tables gives pid the socket tables of one network namespace.
func tables(t *testing.T, root, pid string) {
	t.Helper()
	testfs.File(t, root, pid+"/net/tcp", tcpHead+
		line("0100007F:1F90", "00000000:0000", "0A", "100")+
		line("050200C0:9C40", "097100CB:115C", "01", "4242")+
		line("050200C0:9C42", "097100CB:115D", "02", "4243")+
		"garbage line\n   9: nothex:zz 00000000:0000 0A"+tcpTail+"77"+tcpEnd, 0o444)
	testfs.File(t, root, pid+"/net/tcp6", tcpHead+
		line("0000000000000000FFFF0000050200C0:9C41", "0000000000000000FFFF0000097100CB:01BB", "01", "4244")+
		line("00000000000000000000000001000000:1F91", "00000000000000000000000000000000:0000", "0A", "4245"), 0o444)
	testfs.File(t, root, pid+"/net/udp", tcpHead+
		line("0100007F:0035", "00000000:0000", "07", "300")+
		line("050200C0:D431", "010200C0:0035", "01", "301"), 0o444)
	testfs.File(t, root, pid+"/net/raw", tcpHead+line("00000000:0001", "00000000:0000", "07", "400"), 0o444)
	testfs.File(t, root, pid+"/net/packet", "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n"+
		"0000000000000000 3      3    0003   2     1 0      0      500\n", 0o444)
	testfs.File(t, root, pid+"/net/unix", "Num               RefCount Protocol Flags    Type St Inode Path\n"+
		"0000000000000000: 00000002 00000000 00010000 0001 01 600 /run/x.sock\n", 0o444)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestRead_SocketTables(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 42, 1, "x")
	testfs.Symlink(t, root, "/42/ns/net", netA)
	tables(t, root, "/42")
	socks := snap(t, root).Socks[netA]
	want := map[uint64]Sock{
		100:  {Inode: 100, Family: unix.AF_INET, Proto: "tcp", Local: ap("127.0.0.1:8080"), Remote: ap("0.0.0.0:0"), Listen: true},
		4242: {Inode: 4242, Family: unix.AF_INET, Proto: "tcp", Local: ap("192.0.2.5:40000"), Remote: ap("203.0.113.9:4444")},
		4243: {Inode: 4243, Family: unix.AF_INET, Proto: "tcp", Local: ap("192.0.2.5:40002"), Remote: ap("203.0.113.9:4445"), SynSent: true},
		4244: {Inode: 4244, Family: unix.AF_INET6, Proto: "tcp", Local: ap("192.0.2.5:40001"), Remote: ap("203.0.113.9:443")},
		4245: {Inode: 4245, Family: unix.AF_INET6, Proto: "tcp", Local: ap("[::1]:8081"), Remote: ap("[::]:0"), Listen: true},
		300:  {Inode: 300, Family: unix.AF_INET, Proto: "udp", Local: ap("127.0.0.1:53"), Remote: ap("0.0.0.0:0"), Listen: true},
		301:  {Inode: 301, Family: unix.AF_INET, Proto: "udp", Local: ap("192.0.2.5:54321"), Remote: ap("192.0.2.1:53")},
		400:  {Inode: 400, Family: unix.AF_INET, Proto: "raw", Local: ap("0.0.0.0:1"), Remote: ap("0.0.0.0:0"), Listen: true},
		500:  {Inode: 500, Family: unix.AF_PACKET, Proto: "packet"},
		600:  {Inode: 600, Family: unix.AF_UNIX, Proto: "unix"},
	}
	if len(socks) != len(want) {
		t.Errorf("%d sockets, want %d: %+v", len(socks), len(want), socks)
	}
	for inode, w := range want {
		if socks[inode] != w {
			t.Errorf("inode %d:\ngot  %+v\nwant %+v", inode, socks[inode], w)
		}
	}
}

func TestSockets_FdToSocket(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 42, 1, "sh")
	testfs.Symlink(t, root, "/42/ns/net", netA)
	tables(t, root, "/42")
	testfs.Symlink(t, root, "/42/fd/0", "socket:[4242]")
	testfs.Symlink(t, root, "/42/fd/1", "socket:[4242]")
	testfs.Symlink(t, root, "/42/fd/2", "/dev/null")
	testfs.Symlink(t, root, "/42/fd/3", "socket:[9]")
	testfs.Symlink(t, root, "/42/fd/4", "pipe:[4242]")
	testfs.Symlink(t, root, "/42/fd/10", "socket:[300]")
	testfs.Symlink(t, root, "/42/fd/x", "socket:[100]")
	s := snap(t, root)
	p := s.Procs[42]
	if len(p.FDs) != 4 || p.FDs[0] != 4242 || p.FDs[3] != 9 || p.FDs[10] != 300 {
		t.Fatalf("fds %v", p.FDs)
	}
	got := s.Sockets(p)
	if len(got) != 3 || got[0].FD != 0 || got[1].FD != 1 || got[2].FD != 10 {
		t.Fatalf("sockets %+v", got)
	}
	if got[0].Remote != ap("203.0.113.9:4444") || got[0].Proto != "tcp" || got[2].Proto != "udp" {
		t.Fatalf("sockets %+v", got)
	}
	if o := s.UDPOwner(netA, 53); o != p {
		t.Fatalf("udp owner %+v", o)
	}
	if o := s.UDPOwner(netA, 8080); o != nil {
		t.Fatalf("udp owner of a tcp port: %+v", o)
	}
	if o := s.UDPOwner(netB, 53); o != nil {
		t.Fatalf("udp owner in another netns: %+v", o)
	}
}

func TestRead_TwoNetns(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 42, 1, "host")
	testfs.Symlink(t, root, "/42/ns/net", netA)
	testfs.File(t, root, "/42/net/tcp", tcpHead+line("0100007F:1F90", "00000000:0000", "0A", "7"), 0o444)
	testfs.Symlink(t, root, "/42/fd/3", "socket:[7]")
	mkproc(t, root, 43, 1, "container")
	testfs.Symlink(t, root, "/43/ns/net", netB)
	testfs.File(t, root, "/43/net/tcp", tcpHead+line("050200C0:9C40", "097100CB:115C", "01", "7"), 0o444)
	testfs.Symlink(t, root, "/43/fd/3", "socket:[7]")
	// Same netns as 43; its tables are not read twice.
	mkproc(t, root, 44, 43, "child")
	testfs.Symlink(t, root, "/44/ns/net", netB)
	testfs.Symlink(t, root, "/44/fd/0", "socket:[7]")
	// No readable netns: no sockets.
	mkproc(t, root, 45, 1, "zombie")
	testfs.Symlink(t, root, "/45/fd/0", "socket:[7]")

	s := snap(t, root)
	if a := s.Sockets(s.Procs[42]); len(a) != 1 || !a[0].Listen {
		t.Fatalf("host: %+v", a)
	}
	for _, pid := range []int{43, 44} {
		if b := s.Sockets(s.Procs[pid]); len(b) != 1 || b[0].Remote != ap("203.0.113.9:4444") {
			t.Fatalf("pid %d: %+v", pid, b)
		}
	}
	if z := s.Sockets(s.Procs[45]); len(z) != 0 {
		t.Fatalf("zombie: %+v", z)
	}
}
