// Package proc reads processes and their sockets from a proc mount.
package proc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	maxSmall   = 1 << 16   // stat, status, cgroup
	maxCmdline = 4096      //
	maxTable   = 8 << 20   // one socket table
	maxFDs     = 1 << 16   // descriptors looked at per process
	maxExe     = 256 << 20 // bytes of an executable that are hashed
	maxChain   = 64
)

// Proc is one process as proc showed it.
type Proc struct {
	PID, PPID  int
	UID        uint32
	Start      uint64 // starttime from stat: with PID, the identity of a process
	Comm, Exe  string // Exe is the link text without " (deleted)"
	ExeDeleted bool
	Cmdline    []string       // at most 4096 bytes in total
	Cgroup     string         // the v2 path, e.g. "/system.slice/apache2.service"
	NetNS      string         // link text of ns/net
	FDs        map[int]uint64 // fd → socket inode, sockets only
	Kernel     bool           // no exe and ppid 0 or 2
}

// Snapshot is every process and every socket at one moment.
type Snapshot struct {
	Procs map[int]*Proc
	Socks map[string]map[uint64]Sock // netns → inode → socket
}

// Read takes a snapshot of the proc mount at root. A process that goes away
// while it is being read is left out.
func Read(root string) (*Snapshot, error) {
	d, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Procs: map[int]*Proc{}, Socks: map[string]map[uint64]Sock{}}
	byNS := map[string][]int{}
	for _, name := range names {
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}
		p, err := ReadOne(root, pid)
		if err != nil {
			continue
		}
		s.Procs[pid] = p
		if p.NetNS != "" {
			byNS[p.NetNS] = append(byNS[p.NetNS], pid)
		}
	}
	for ns, pids := range byNS {
		sort.Ints(pids)
		s.Socks[ns] = readTables(root, pids)
	}
	return s, nil
}

// ReadOne reads one process. Only stat is required; whatever else cannot be
// read is left empty.
func ReadOne(root string, pid int) (*Proc, error) {
	dir := filepath.Join(root, strconv.Itoa(pid))
	stat, err := readCapped(filepath.Join(dir, "stat"), maxSmall)
	if err != nil {
		return nil, err
	}
	p := &Proc{PID: pid, FDs: map[int]uint64{}}
	if !parseStat(string(stat), p) {
		return nil, fmt.Errorf("pid %d: malformed stat", pid)
	}
	if status, err := readCapped(filepath.Join(dir, "status"), maxSmall); err == nil {
		p.UID = realUID(string(status))
	}
	if cmdline, err := readCapped(filepath.Join(dir, "cmdline"), maxCmdline); err == nil {
		if cmdline = bytes.TrimRight(cmdline, "\x00"); len(cmdline) > 0 {
			p.Cmdline = strings.Split(string(cmdline), "\x00")
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe, p.ExeDeleted = strings.CutSuffix(exe, " (deleted)")
	}
	if cgroup, err := readCapped(filepath.Join(dir, "cgroup"), maxSmall); err == nil {
		for _, l := range strings.Split(string(cgroup), "\n") {
			if path, ok := strings.CutPrefix(l, "0::"); ok {
				p.Cgroup = path
			}
		}
	}
	p.NetNS, _ = os.Readlink(filepath.Join(dir, "ns/net"))
	p.Kernel = p.Exe == "" && (p.PPID == 0 || p.PPID == 2)
	readFDs(filepath.Join(dir, "fd"), p)
	return p, nil
}

// parseStat fills comm, ppid and start time. The comm is whatever the
// process chose, brackets and newlines included, so it is taken as all that
// lies between the first "(" and the last ")".
func parseStat(stat string, p *Proc) bool {
	open, shut := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || shut < open {
		return false
	}
	p.Comm = stat[open+1 : shut]
	f := strings.Fields(stat[shut+1:])
	if len(f) < 20 {
		return false
	}
	ppid, err1 := strconv.Atoi(f[1])
	start, err2 := strconv.ParseUint(f[19], 10, 64)
	p.PPID, p.Start = ppid, start
	return err1 == nil && err2 == nil
}

func realUID(status string) uint32 {
	for _, l := range strings.Split(status, "\n") {
		if rest, ok := strings.CutPrefix(l, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				uid, _ := strconv.ParseUint(f[0], 10, 32)
				return uint32(uid)
			}
		}
	}
	return 0
}

func readFDs(dir string, p *Proc) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	names, _ := d.Readdirnames(maxFDs)
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		link, err := os.Readlink(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		num, ok := strings.CutPrefix(link, "socket:[")
		if !ok {
			continue
		}
		if inode, err := strconv.ParseUint(strings.TrimSuffix(num, "]"), 10, 64); err == nil {
			p.FDs[fd] = inode
		}
	}
}

// readCapped reads at most max bytes of a regular file; what lies beyond is
// dropped. Files in proc report no size, and a command line or a socket
// table is as long as the adversary makes it, so a file over the cap is cut
// short rather than refused.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, max))
}

type exeKey struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

var exeCache = struct {
	sync.Mutex
	sums map[exeKey]string
}{sums: map[exeKey]string{}}

// ExeHash is the SHA-256 of the program p runs, read through its exe link
// so that a deleted or replaced file on disk does not stand in for it.
func ExeHash(root string, p *Proc) (string, error) {
	f, err := os.OpenFile(filepath.Join(root, strconv.Itoa(p.PID), "exe"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return "", errors.New("exe is not a regular file")
	}
	key := exeKey{uint64(st.Dev), st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano()}
	exeCache.Lock()
	sum, ok := exeCache.sums[key]
	exeCache.Unlock()
	if ok {
		return sum, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxExe)); err != nil {
		return "", err
	}
	sum = hex.EncodeToString(h.Sum(nil))
	exeCache.Lock()
	if len(exeCache.sums) >= 4096 {
		clear(exeCache.sums)
	}
	exeCache.sums[key] = sum
	exeCache.Unlock()
	return sum, nil
}
