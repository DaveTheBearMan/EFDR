package respond

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/detect"
	"xdr/internal/pathenc"
	"xdr/internal/proc"
)

const ns = "net:[1]"

func mk(pid, ppid int, exe string, fds map[int]uint64) *proc.Proc {
	if fds == nil {
		fds = map[int]uint64{}
	}
	return &proc.Proc{PID: pid, PPID: ppid, UID: 1000, Start: uint64(1000 + pid), Comm: path.Base(exe), Exe: exe, NetNS: ns, FDs: fds}
}

func TestDecide(t *testing.T) {
	networkd := "/usr/lib/systemd/systemd-networkd"
	base := &baseline.Baseline{Files: map[string]baseline.FileEntry{}}
	for _, exe := range []string{"/usr/bin/curl", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/nc.openbsd", "/usr/sbin/apache2", networkd} {
		base.Files[pathenc.Encode(exe)] = baseline.FileEntry{SHA256: "h:" + exe}
	}
	p := &detect.Policy{
		Cfg: &config.Config{
			Scored:    []config.Port{{Proto: "tcp", Port: 80}},
			GuardExes: []string{"/usr/sbin/apache2"},
		},
		Base:  base,
		Gray:  map[uint32]bool{2001: true},
		Local: func(netip.Addr) bool { return false },
		Hash:  func(pr *proc.Proc) string { return "h:" + pr.Exe },
	}
	gray := mk(20, 1, "/usr/bin/bash", nil)
	gray.UID = 2001
	boxed := mk(40, 1, "/usr/bin/curl", nil)
	boxed.Cgroup = "/system.slice/docker-" + strings.Repeat("0123456789abcdef", 4) + ".scope"
	s := &proc.Snapshot{Procs: map[int]*proc.Proc{}, Socks: map[string]map[uint64]proc.Sock{ns: {
		80: {Inode: 80, Family: unix.AF_INET, Proto: "tcp", Local: netip.MustParseAddrPort("0.0.0.0:80"), Listen: true},
	}}}
	for _, pr := range []*proc.Proc{
		mk(1, 0, "/usr/lib/systemd/systemd", nil),
		mk(10, 1, "/usr/sbin/apache2", map[int]uint64{4: 80}),
		mk(11, 10, "/usr/bin/dash", nil),
		mk(12, 1, "/tmp/squatter", map[int]uint64{3: 80}),
		gray,
		mk(21, 20, "/tmp/tool", nil), // root-owned, started from the gray session
		mk(30, 1, "/usr/bin/curl", nil),
		mk(31, 1, "/usr/bin/bash", nil),
		mk(32, 1, "/tmp/implant", nil),
		mk(33, 1, networkd, nil),
		mk(34, 1, "/usr/bin/nc.openbsd", nil),
		boxed,
	} {
		s.Procs[pr.PID] = pr
	}
	s.Procs[21].UID = 0

	for name, c := range map[string]struct {
		pid  int
		kind string
		want string
	}{
		"guarded, egress":             {10, "egress", "held"},
		"guarded, revshell":           {10, "revshell-stdio", "held"},
		"guarded by scored port":      {12, "listener", "held"},
		"gray, egress":                {20, "egress", "alert"},
		"gray, revshell":              {20, "revshell-stdio", "kill"},
		"gray, service-shell":         {20, "service-shell", "kill"},
		"child of gray, rawsock":      {21, "rawsock", "alert"},
		"baseline curl, egress":       {30, "egress", "alert"},
		"baseline bash, egress":       {31, "egress", "kill"},
		"not baseline, listener":      {32, "listener", "kill"},
		"baseline networkd, listener": {33, "listener", "alert"},
		"baseline nc, listener":       {34, "listener", "kill"},
		"container, egress":           {40, "egress", "kill"},
		"sh under apache":             {11, "service-shell", "kill"},
		"baseline curl, dns":          {30, "dns", "alert"},
		"not baseline, dns":           {32, "dns", "kill"},
	} {
		d := detect.Detection{Kind: c.kind, PID: c.pid, Start: uint64(1000 + c.pid)}
		if got := Decide(d, s, p); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	for name, d := range map[string]detect.Detection{
		"NoKill":           {Kind: "listener", PID: 32, Start: 1032, NoKill: true},
		"NoKill revshell":  {Kind: "revshell-stdio", PID: 32, Start: 1032, NoKill: true},
		"gone":             {Kind: "revshell-stdio", PID: 99, Start: 1099},
		"gone when judged": {Kind: "service-shell", PID: 32},
		"pid reused":       {Kind: "revshell-stdio", PID: 32, Start: 5},
	} {
		if got := Decide(d, s, p); got != "alert" {
			t.Errorf("%s: %s, want alert", name, got)
		}
	}
}

// state is the one-letter state of pid and its session, "" when it is not
// there.
func state(pid int) (st string, session int) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	fmt.Sscan(f[3], &session)
	return f[0], session
}

func alive(pid int) bool {
	st, _ := state(pid)
	return st != "" && st != "Z"
}

func start(t *testing.T, pid int) uint64 {
	t.Helper()
	pr, err := proc.ReadOne("/proc", pid)
	if err != nil {
		t.Fatal(err)
	}
	return pr.Start
}

// spawn runs script under sh and waits until it has the wanted number of
// descendants. The whole process group is killed when the test ends.
func spawn(t *testing.T, script string, descendants int) (pid int, desc []int) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go cmd.Wait()
	pid = cmd.Process.Pid
	t.Cleanup(func() { syscall.Kill(-pid, syscall.SIGKILL) })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		s, err := proc.Read("/proc")
		if err != nil {
			t.Fatal(err)
		}
		if desc = s.Descendants(pid); len(desc) >= descendants {
			return pid, desc
		}
		if time.Now().After(deadline) {
			t.Fatalf("%q: %d descendants, want %d", script, len(desc), descendants)
		}
	}
}

func waitGone(t *testing.T, pids ...int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for _, pid := range pids {
		for alive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("pid %d still runs", pid)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func children(t *testing.T, pid int) (out []int) {
	t.Helper()
	s, err := proc.Read("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range s.Procs {
		if pr.PPID == pid {
			out = append(out, pr.PID)
		}
	}
	slices.Sort(out)
	return out
}

const branch = "sleep 60 & sleep 60 & wait"

func TestKillTree_KillsWholeBranch(t *testing.T) {
	pid, desc := spawn(t, branch, 2)
	killed, err := KillTree("/proc", pid, start(t, pid), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]int{pid}, desc...)
	slices.Sort(want)
	got := slices.Clone(killed)
	slices.Sort(got)
	if !slices.Equal(got, want) || killed[0] != pid {
		t.Fatalf("killed %v, want %v with %d first", killed, want, pid)
	}
	waitGone(t, want...)
}

func TestKillTree_LeavesParentAndSiblings(t *testing.T) {
	pid, _ := spawn(t, "sh -c '"+branch+"' & sh -c '"+branch+"' & wait", 6)
	kids := children(t, pid)
	if len(kids) != 2 {
		t.Fatalf("children %v", kids)
	}
	doomed, spared := kids[0], kids[1]
	doomedKids, sparedKids := children(t, doomed), children(t, spared)
	killed, err := KillTree("/proc", doomed, start(t, doomed), nil)
	if err != nil || len(killed) != 3 {
		t.Fatalf("killed %v, %v", killed, err)
	}
	waitGone(t, append(doomedKids, doomed)...)
	for _, p := range append(sparedKids, spared, pid) {
		if st, _ := state(p); st != "S" && st != "R" {
			t.Errorf("pid %d: state %q, want it running", p, st)
		}
	}
}

func TestKillTree_PidReused(t *testing.T) {
	pid, desc := spawn(t, branch, 2)
	killed, err := KillTree("/proc", pid, start(t, pid)+1, nil)
	if !errors.Is(err, ErrGone) || len(killed) != 0 {
		t.Fatalf("killed %v, err %v", killed, err)
	}
	for _, p := range append(desc, pid) {
		if st, _ := state(p); st != "S" && st != "R" {
			t.Errorf("pid %d: state %q, want it running (not stopped)", p, st)
		}
	}
}

func TestKillTree_ProtectedSkipped(t *testing.T) {
	// One child is a branch of its own: what a protected process started
	// is left alone with it.
	pid, _ := spawn(t, "sh -c '"+branch+"' & sleep 60 & wait", 4)
	var guarded int
	for _, k := range children(t, pid) {
		if len(children(t, k)) == 2 {
			guarded = k
		}
	}
	if guarded == 0 {
		t.Fatal("no inner branch")
	}
	spared := append(children(t, guarded), guarded)
	killed, err := KillTree("/proc", pid, start(t, pid), func(pr *proc.Proc) bool { return pr.PID == guarded })
	if err != nil || len(killed) != 2 {
		t.Fatalf("killed %v, %v", killed, err)
	}
	waitGone(t, killed...)
	for _, p := range spared {
		if st, _ := state(p); st != "S" && st != "R" {
			t.Errorf("pid %d: state %q, want it running", p, st)
		}
		if slices.Contains(killed, p) {
			t.Errorf("pid %d reported killed", p)
		}
	}
}

func TestKillTree_ProtectedRoot(t *testing.T) {
	pid, desc := spawn(t, branch, 2)
	killed, err := KillTree("/proc", pid, start(t, pid), func(pr *proc.Proc) bool { return pr.PID == pid })
	if err != nil || len(killed) != 0 {
		t.Fatalf("killed %v, %v", killed, err)
	}
	for _, p := range append(desc, pid) {
		if !alive(p) {
			t.Errorf("pid %d died", p)
		}
	}
}

func TestKillTree_NeverSelfOrAncestors(t *testing.T) {
	// The test binary's parent is go test: asking for that tree must not
	// take this process, or anything, down.
	parent := os.Getppid()
	done := make(chan struct{})
	go func() {
		defer close(done)
		KillTree("/proc", os.Getpid(), start(t, os.Getpid()), nil)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no return")
	}
	if !alive(parent) {
		t.Fatal("parent died")
	}
}

func TestKillTree_AlreadyExited(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if killed, err := KillTree("/proc", cmd.Process.Pid, 1, nil); !errors.Is(err, ErrGone) || killed != nil {
		t.Fatalf("killed %v, err %v", killed, err)
	}
	if _, err := KillTree("/proc", -1, 1, nil); !errors.Is(err, ErrGone) {
		t.Fatalf("pid -1: %v", err)
	}
}

func TestKillTree_ForkerCannotOutrun(t *testing.T) {
	// The sleeps are too short-lived to wait for one in a snapshot.
	pid, _ := spawn(t, "while :; do sleep 0.01 & done", 0)
	time.Sleep(100 * time.Millisecond)
	if _, err := KillTree("/proc", pid, start(t, pid), nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	s, err := proc.Read("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range s.Procs {
		st, session := state(pr.PID)
		if st == "" || st == "Z" {
			continue
		}
		if session == pid || slices.ContainsFunc(s.Chain(pr.PID), func(a *proc.Proc) bool { return a.PID == pid }) {
			t.Errorf("pid %d (%s) outlived the kill", pr.PID, pr.Comm)
		}
	}
}
