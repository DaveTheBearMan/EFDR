package proc

import (
	"encoding/hex"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Sock is one socket from a namespace's socket tables.
type Sock struct {
	Inode         uint64
	Family        int            // unix.AF_INET, AF_INET6, AF_PACKET, AF_UNIX
	Proto         string         // "tcp", "udp", "raw", "packet", "unix"
	Local, Remote netip.AddrPort // v4-mapped v6 addresses are unmapped
	Listen        bool           // tcp LISTEN; udp/raw bound with no remote
	SynSent       bool
}

// FDSock is a socket as one process holds it.
type FDSock struct {
	FD int
	Sock
}

var inetTables = []struct {
	file   string
	family int
	proto  string
}{
	{"tcp", unix.AF_INET, "tcp"},
	{"tcp6", unix.AF_INET6, "tcp"},
	{"udp", unix.AF_INET, "udp"},
	{"udp6", unix.AF_INET6, "udp"},
	{"raw", unix.AF_INET, "raw"},
	{"raw6", unix.AF_INET6, "raw"},
}

// readTables reads the socket tables of the namespace the pids share.
func readTables(root string, pids []int) map[uint64]Sock {
	socks := map[uint64]Sock{}
	// table reads one file through the first pid that still has it.
	table := func(file string, each func(fields []string)) {
		for i, pid := range pids {
			if i == 3 {
				return
			}
			data, err := readCapped(filepath.Join(root, strconv.Itoa(pid), "net", file), maxTable)
			if err != nil {
				continue
			}
			lines := strings.Split(string(data), "\n")
			for _, l := range lines[:len(lines)-1] { // the last piece is empty or cut short
				each(strings.Fields(l))
			}
			return
		}
	}
	for _, tb := range inetTables {
		table(tb.file, func(f []string) {
			if s, ok := parseInet(f, tb.family, tb.proto); ok {
				socks[s.Inode] = s
			}
		})
	}
	table("packet", func(f []string) {
		if inode, ok := inodeAt(f, 8); ok {
			socks[inode] = Sock{Inode: inode, Family: unix.AF_PACKET, Proto: "packet"}
		}
	})
	table("unix", func(f []string) {
		if inode, ok := inodeAt(f, 6); ok {
			socks[inode] = Sock{Inode: inode, Family: unix.AF_UNIX, Proto: "unix"}
		}
	})
	return socks
}

func inodeAt(f []string, i int) (uint64, bool) {
	if len(f) <= i {
		return 0, false
	}
	inode, err := strconv.ParseUint(f[i], 10, 64)
	return inode, err == nil && inode != 0
}

// parseInet reads one line of a tcp, udp or raw table:
//
//	sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode ...
func parseInet(f []string, family int, proto string) (Sock, bool) {
	inode, ok := inodeAt(f, 9)
	if !ok {
		return Sock{}, false
	}
	local, ok1 := parseAddr(f[1])
	remote, ok2 := parseAddr(f[2])
	state, err := strconv.ParseUint(f[3], 16, 8)
	if !ok1 || !ok2 || err != nil {
		return Sock{}, false
	}
	s := Sock{Inode: inode, Family: family, Proto: proto, Local: local, Remote: remote}
	if proto == "tcp" {
		s.Listen, s.SynSent = state == 0x0A, state == 0x02
	} else {
		s.Listen = remote.Addr().IsUnspecified() && remote.Port() == 0
	}
	return s, true
}

// parseAddr reads "ADDR:PORT" as the kernel prints it: the address is hex
// of 32-bit words in host byte order, the port plain hex.
func parseAddr(s string) (netip.AddrPort, bool) {
	addr, port, ok := strings.Cut(s, ":")
	if !ok || len(addr) != 8 && len(addr) != 32 {
		return netip.AddrPort{}, false
	}
	b, err1 := hex.DecodeString(addr)
	p, err2 := strconv.ParseUint(port, 16, 16)
	if err1 != nil || err2 != nil {
		return netip.AddrPort{}, false
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), true
}

// Sockets lists the sockets p holds, by descriptor. A descriptor whose
// socket is in none of the tables of p's namespace is left out.
func (s *Snapshot) Sockets(p *Proc) []FDSock {
	table := s.Socks[p.NetNS]
	var out []FDSock
	for fd, inode := range p.FDs {
		if sock, ok := table[inode]; ok {
			out = append(out, FDSock{FD: fd, Sock: sock})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FD < out[j].FD })
	return out
}

// UDPOwner finds the process holding the UDP socket bound to port in netns.
func (s *Snapshot) UDPOwner(netns string, port uint16) *Proc {
	var owner *Proc
	for _, p := range s.Procs {
		if p.NetNS != netns || owner != nil && owner.PID < p.PID {
			continue
		}
		for _, inode := range p.FDs {
			if sock, ok := s.Socks[netns][inode]; ok && sock.Proto == "udp" && sock.Local.Port() == port {
				owner = p
				break
			}
		}
	}
	return owner
}
