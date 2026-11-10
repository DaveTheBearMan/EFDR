package sensor

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// wire builds one 184-byte event as the kernel side writes it.
func wire(kind, pid, ppid, uid uint32, family, typ, port uint16, addr []byte, comm, filename string) []byte {
	b := make([]byte, 184)
	le := binary.LittleEndian
	le.PutUint32(b[0:], kind)
	le.PutUint32(b[4:], pid)
	le.PutUint32(b[8:], ppid)
	le.PutUint32(b[12:], uid)
	le.PutUint16(b[16:], family)
	le.PutUint16(b[18:], typ)
	le.PutUint16(b[20:], port)
	copy(b[24:40], addr)
	copy(b[40:56], comm)
	copy(b[56:184], filename)
	return b
}

func TestDecode_Connect4(t *testing.T) {
	ev, ok := decode(wire(2, 77, 0, 0, unix.AF_INET, 6, 4444, []byte{203, 0, 113, 9}, "", ""))
	if want := (Event{Kind: Connect, PID: 77, Proto: "tcp", Dst: netip.MustParseAddrPort("203.0.113.9:4444")}); !ok || ev != want {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestDecode_ConnectAndSend6(t *testing.T) {
	v6 := netip.MustParseAddr("2001:db8::9").As16()
	ev, ok := decode(wire(3, 77, 0, 33, unix.AF_INET6, 17, 53, v6[:], "dnscat", ""))
	if want := (Event{Kind: Send, PID: 77, UID: 33, Comm: "dnscat", Proto: "udp", Dst: netip.MustParseAddrPort("[2001:db8::9]:53")}); !ok || ev != want {
		t.Fatalf("%+v %v", ev, ok)
	}
	// A v4-mapped destination is the IPv4 one.
	mapped := netip.MustParseAddr("::ffff:203.0.113.9").As16()
	ev, ok = decode(wire(2, 77, 0, 0, unix.AF_INET6, 6, 443, mapped[:], "", ""))
	if !ok || ev.Dst != netip.MustParseAddrPort("203.0.113.9:443") {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestDecode_Exec(t *testing.T) {
	b := wire(1, 500, 499, 33, 0, 0, 0, nil, "sh", "/bin/sh")
	// Whatever follows the NUL in a field is not part of the string.
	copy(b[40+3:], "junk")
	copy(b[56+8:], "junk")
	ev, ok := decode(b)
	if want := (Event{Kind: Exec, PID: 500, PPID: 499, UID: 33, Comm: "sh", Filename: "/bin/sh"}); !ok || ev != want {
		t.Fatalf("%+v %v", ev, ok)
	}
	// A field filled to the brim has no NUL.
	long := string(make([]byte, 0, 200))
	for len(long) < 200 {
		long += "/abcdefghi"
	}
	ev, ok = decode(wire(1, 500, 499, 0, 0, 0, 0, nil, "0123456789abcdefXX", long))
	if !ok || ev.Comm != "0123456789abcdef" || ev.Filename != long[:128] {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestDecode_Socket(t *testing.T) {
	ev, ok := decode(wire(4, 77, 0, 0, unix.AF_PACKET, unix.SOCK_RAW, 0, nil, "sniff", ""))
	if want := (Event{Kind: Socket, PID: 77, Comm: "sniff", Family: unix.AF_PACKET, SockType: unix.SOCK_RAW}); !ok || ev != want {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestDecode_ShortOrUnknownKind(t *testing.T) {
	good := wire(2, 77, 0, 0, unix.AF_INET, 6, 4444, []byte{203, 0, 113, 9}, "", "")
	for name, b := range map[string][]byte{
		"short":          good[:183],
		"empty":          nil,
		"kind 0":         wire(0, 77, 0, 0, unix.AF_INET, 6, 4444, []byte{203, 0, 113, 9}, "", ""),
		"kind 5":         wire(5, 77, 0, 0, unix.AF_INET, 6, 4444, []byte{203, 0, 113, 9}, "", ""),
		"pid 0":          wire(2, 0, 0, 0, unix.AF_INET, 6, 4444, []byte{203, 0, 113, 9}, "", ""),
		"connect, icmp":  wire(2, 77, 0, 0, unix.AF_INET, 1, 0, []byte{203, 0, 113, 9}, "", ""),
		"connect, af 99": wire(2, 77, 0, 0, 99, 6, 4444, []byte{203, 0, 113, 9}, "", ""),
	} {
		if ev, ok := decode(b); ok {
			t.Errorf("%s: %+v", name, ev)
		}
	}
}

func ebpfSource(t *testing.T) Source {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	src, err := NewEBPF("/sys/fs/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if src.Name() != "ebpf" {
		t.Fatalf("name %q", src.Name())
	}
	t.Cleanup(func() {
		if err := src.Close(); err != nil {
			t.Error(err)
		}
	})
	return src
}

// await returns the first event match accepts.
func await(t *testing.T, src Source, d time.Duration, match func(Event) bool) (Event, bool) {
	t.Helper()
	timeout := time.After(d)
	for {
		select {
		case ev, ok := <-src.Events():
			if !ok {
				t.Fatal("events channel closed")
			}
			if match(ev) {
				return ev, true
			}
		case <-timeout:
			return Event{}, false
		}
	}
}

func TestKernel_EBPF_Exec(t *testing.T) {
	src := ebpfSource(t)
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	ev, ok := await(t, src, 2*time.Second, func(ev Event) bool { return ev.Kind == Exec && ev.PID == cmd.Process.Pid })
	if !ok {
		t.Fatal("no exec event")
	}
	if ev.Filename != "/bin/true" || ev.PPID != os.Getpid() || ev.Comm != "true" || ev.UID != 0 {
		t.Fatalf("%+v", ev)
	}
}

func TestKernel_EBPF_ConnectUDP(t *testing.T) {
	src := ebpfSource(t)
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil { // no packet leaves
		defer c.Close()
	}
	mine := func(ev Event) bool { return ev.Kind == Connect && ev.PID == os.Getpid() }
	ev, ok := await(t, src, 2*time.Second, mine)
	if !ok {
		t.Fatal("no connect event")
	}
	if ev.Proto != "udp" || ev.Dst != netip.MustParseAddrPort("192.0.2.1:9") || ev.Comm == "" {
		t.Fatalf("%+v", ev)
	}
}

func TestKernel_EBPF_ConnectTCP6(t *testing.T) {
	src := ebpfSource(t)
	d := net.Dialer{Timeout: 100 * time.Millisecond}
	if c, err := d.Dial("tcp", "[2001:db8::9]:4444"); err == nil {
		c.Close()
	}
	ev, ok := await(t, src, 2*time.Second, func(ev Event) bool { return ev.Kind == Connect && ev.PID == os.Getpid() })
	if !ok || ev.Proto != "tcp" || ev.Dst != netip.MustParseAddrPort("[2001:db8::9]:4444") {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestKernel_EBPF_Send(t *testing.T) {
	src := ebpfSource(t)
	// In a network namespace of its own the datagram has nowhere to go.
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with its namespace
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
		if err != nil {
			done <- err
			return
		}
		defer pc.Close()
		pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 53})
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ev, ok := await(t, src, 2*time.Second, func(ev Event) bool { return ev.Kind == Send && ev.PID == os.Getpid() })
	if !ok || ev.Proto != "udp" || ev.Dst != netip.MustParseAddrPort("192.0.2.1:53") {
		t.Fatalf("%+v %v", ev, ok)
	}
}

func TestKernel_EBPF_LoopbackSkipped(t *testing.T) {
	src := ebpfSource(t)
	for _, dst := range []string{"127.0.0.1:9", "127.9.9.9:9", "[::1]:9", "[::ffff:127.0.0.1]:9"} {
		if c, err := net.Dial("udp", dst); err == nil {
			c.Write([]byte("x"))
			c.Close()
		}
	}
	if ev, ok := await(t, src, 500*time.Millisecond, func(ev Event) bool {
		return (ev.Kind == Connect || ev.Kind == Send) && ev.PID == os.Getpid()
	}); ok {
		t.Fatalf("%+v", ev)
	}
}

func TestKernel_EBPF_RawSocket(t *testing.T) {
	src := ebpfSource(t)
	for name, c := range map[string]struct{ family, typ, proto int }{
		"packet": {unix.AF_PACKET, unix.SOCK_RAW, 0},
		"raw":    {unix.AF_INET, unix.SOCK_RAW | unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP},
	} {
		fd, err := unix.Socket(c.family, c.typ, c.proto)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		ev, ok := await(t, src, 2*time.Second, func(ev Event) bool { return ev.Kind == Socket && ev.PID == os.Getpid() })
		if !ok || ev.Family != c.family || ev.SockType&0xf != unix.SOCK_RAW {
			t.Fatalf("%s: %+v %v", name, ev, ok)
		}
	}
	// A stream socket, and the netlink sockets every tool opens, are not news.
	for _, c := range [][2]int{{unix.AF_INET, unix.SOCK_STREAM}, {unix.AF_NETLINK, unix.SOCK_RAW}} {
		if fd, err := unix.Socket(c[0], c[1], 0); err == nil {
			unix.Close(fd)
		}
	}
	if ev, ok := await(t, src, 300*time.Millisecond, func(ev Event) bool { return ev.Kind == Socket && ev.PID == os.Getpid() }); ok {
		t.Fatalf("%+v", ev)
	}
}

func TestKernel_EBPF_BadCgroup(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	if src, err := NewEBPF("/nonexistent/cgroup"); err == nil {
		src.Close()
		t.Fatal("no error")
	}
	// What the failed attempt attached is gone: a second sensor works.
	src := ebpfSource(t)
	exec.Command("/bin/true").Run()
	if _, ok := await(t, src, 2*time.Second, func(ev Event) bool { return ev.Kind == Exec }); !ok {
		t.Fatal("no exec event")
	}
}
