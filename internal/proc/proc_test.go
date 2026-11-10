package proc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xdr/internal/testfs"
)

const netA, netB = "net:[4026531840]", "net:[4026532001]"

// mkproc writes the least a process directory needs: stat and status.
func mkproc(t *testing.T, root string, pid, ppid int, comm string) {
	t.Helper()
	dir := fmt.Sprintf("/%d", pid)
	stat := fmt.Sprintf("%d (%s) S %d 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 %d 0 0\n", pid, comm, ppid, 1000+pid)
	testfs.File(t, root, dir+"/stat", stat, 0o444)
	testfs.File(t, root, dir+"/status", "Name:\tx\nUid:\t33\t0\t0\t0\nGid:\t33\t33\t33\t33\n", 0o444)
}

func snap(t *testing.T, root string) *Snapshot {
	t.Helper()
	s, err := Read(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRead_Process(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 1, 0, "systemd")
	mkproc(t, root, 42, 1, "a) (b")
	testfs.File(t, root, "/42/cmdline", "/bin/sh\x00-c\x00echo hi\x00", 0o444)
	testfs.Symlink(t, root, "/42/exe", "/tmp/x (deleted)")
	testfs.File(t, root, "/42/cgroup", "1:name=systemd:/ignored\n0::/system.slice/apache2.service\n", 0o444)
	testfs.Symlink(t, root, "/42/ns/net", netA)
	testfs.Symlink(t, root, "/1/exe", "/usr/lib/systemd/systemd")
	mkproc(t, root, 2, 0, "kthreadd")
	mkproc(t, root, 7, 2, "kworker/0:1")
	testfs.File(t, root, "/uptime", "1 1\n", 0o444)
	testfs.File(t, root, "/self/stat", "garbage", 0o444)

	s := snap(t, root)
	if len(s.Procs) != 4 {
		t.Fatalf("procs %v", s.Procs)
	}
	p := s.Procs[42]
	want := &Proc{
		PID: 42, PPID: 1, UID: 33, Start: 1042, Comm: "a) (b", Exe: "/tmp/x", ExeDeleted: true,
		Cmdline: []string{"/bin/sh", "-c", "echo hi"}, Cgroup: "/system.slice/apache2.service",
		NetNS: netA, FDs: map[int]uint64{},
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("got  %+v\nwant %+v", p, want)
	}
	if p1 := s.Procs[1]; p1.Kernel || p1.Exe != "/usr/lib/systemd/systemd" || p1.ExeDeleted {
		t.Fatalf("pid 1: %+v", p1)
	}
	if !s.Procs[2].Kernel || !s.Procs[7].Kernel {
		t.Fatal("kernel threads not marked")
	}
	one, err := ReadOne(root, 42)
	if err != nil || !reflect.DeepEqual(one, want) {
		t.Fatalf("ReadOne: %+v %v", one, err)
	}
	if _, err := ReadOne(root, 999); err == nil {
		t.Fatal("ReadOne of a missing pid: no error")
	}
}

func TestRead_HostileProc(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 5, 1, "evil\nname")
	testfs.File(t, root, "/5/cmdline", strings.Repeat("A", 1<<20), 0o444)
	// A pid that vanished between the listing and the read.
	testfs.File(t, root, "/6/cmdline", "x", 0o444)
	// Stat lines no kernel writes.
	testfs.File(t, root, "/8/stat", "8 no parens here", 0o444)
	testfs.File(t, root, "/9/stat", "9 (x) S notanumber", 0o444)
	testfs.File(t, root, "/10/stat", "10 (x)", 0o444)
	// A fifo where a file should be must not block the sweep.
	mkproc(t, root, 11, 1, "fifo")
	testfs.Fifo(t, root, "/11/cmdline")
	testfs.Fifo(t, root, "/12/stat")

	done := make(chan *Snapshot, 1)
	go func() { done <- snap(t, root) }()
	var s *Snapshot
	select {
	case s = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked")
	}
	if len(s.Procs) != 2 {
		t.Fatalf("procs %v", s.Procs)
	}
	p := s.Procs[5]
	if p.Comm != "evil\nname" {
		t.Fatalf("comm %q", p.Comm)
	}
	total := 0
	for _, a := range p.Cmdline {
		total += len(a)
	}
	if total == 0 || total > 4096 {
		t.Fatalf("cmdline kept %d bytes", total)
	}
	if s.Procs[11].Cmdline != nil {
		t.Fatalf("cmdline from a fifo: %q", s.Procs[11].Cmdline)
	}
}

func TestExeHash_FollowsExeAndTracksChange(t *testing.T) {
	root := testfs.Root(t)
	bin := filepath.Join(t.TempDir(), "tool")
	write := func(content string, mtime time.Time) string {
		if err := os.WriteFile(bin, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(bin, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}
	mkproc(t, root, 42, 1, "tool")
	testfs.Symlink(t, root, "/42/exe", bin)
	p := snap(t, root).Procs[42]

	want := write("first", time.Unix(1_000_000, 0))
	for i := 0; i < 2; i++ { // the second answer comes from the cache
		if got, err := ExeHash(root, p); err != nil || got != want {
			t.Fatalf("hash %q %v, want %q", got, err, want)
		}
	}
	want = write("other", time.Unix(2_000_000, 0)) // same size
	if got, err := ExeHash(root, p); err != nil || got != want {
		t.Fatalf("after rewrite: hash %q %v, want %q", got, err, want)
	}
	mkproc(t, root, 43, 1, "gone")
	if _, err := ExeHash(root, snap(t, root).Procs[43]); err == nil {
		t.Fatal("no exe: no error")
	}
}

func TestRead_LiveProc(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	s := snap(t, "/proc")
	p := s.Procs[os.Getpid()]
	if p == nil {
		t.Fatal("this process is not in the snapshot")
	}
	exe, _ := os.Executable()
	if p.Exe != exe || p.ExeDeleted || p.Kernel || p.PPID != os.Getppid() || p.UID != uint32(os.Getuid()) || p.Start == 0 {
		t.Fatalf("%+v", p)
	}
	if len(p.Cmdline) == 0 || p.Cmdline[0] != os.Args[0] || p.NetNS == "" || !strings.HasPrefix(p.Cgroup, "/") {
		t.Fatalf("%+v", p)
	}
	var listening, dialed, udp bool
	for _, fs := range s.Sockets(p) {
		listening = listening || fs.Proto == "tcp" && fs.Listen && fs.Local.String() == l.Addr().String()
		dialed = dialed || fs.Proto == "tcp" && !fs.Listen && fs.Remote.String() == l.Addr().String()
		udp = udp || fs.Proto == "udp" && fs.Listen && fs.Local.String() == u.LocalAddr().String()
	}
	if !listening || !dialed || !udp {
		t.Fatalf("listening %v, dialed %v, udp %v in %+v", listening, dialed, udp, s.Sockets(p))
	}
	if o := s.UDPOwner(p.NetNS, uint16(u.LocalAddr().(*net.UDPAddr).Port)); o != p {
		t.Fatalf("udp owner %+v", o)
	}
	if chain := s.Chain(p.PID); len(chain) < 2 || chain[len(chain)-1].PID != 1 {
		t.Fatalf("chain %v", pids(chain))
	}
	if sum, err := ExeHash("/proc", p); err != nil || len(sum) != 64 {
		t.Fatalf("exe hash %q %v", sum, err)
	}
}
