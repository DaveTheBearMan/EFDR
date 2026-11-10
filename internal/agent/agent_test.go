package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"xdr/internal/config"
	"xdr/internal/detect"
	"xdr/internal/dnsguard"
	"xdr/internal/fw"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/proc"
	"xdr/internal/respond"
	"xdr/internal/sensor"
)

const (
	selfPID = 4242
	netns   = "net:[4026531840]"
)

type fakeFW struct {
	applied []fw.Ruleset
	drift   bool
	err     error
}

func (f *fakeFW) Apply(rs fw.Ruleset) error {
	f.applied = append(f.applied, rs)
	if f.err == nil {
		f.drift = false
	}
	return f.err
}
func (f *fakeFW) Drifted() (bool, error) { return f.drift, nil }

type killCall struct {
	pid     int
	start   uint64
	protect func(*proc.Proc) bool
}

type rig struct {
	a       *agent
	fw      *fakeFW
	kills   []killCall
	killed  []int // what the fake kill reports besides the pid itself
	killErr error
	got     []incident.Incident
	now     time.Time
	root    string
	snap    *proc.Snapshot
	reads   int
}

func pfx(s string) config.Net { return config.Net{Prefix: netip.MustParsePrefix(s)} }

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{fw: &fakeFW{}, now: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC), root: t.TempDir()}
	cfg := &config.Config{
		Host:      "web01",
		Jump:      []config.Net{pfx("192.0.2.7/32")},
		SSHPort:   22,
		XDRPorts:  []uint16{7443},
		Scored:    []config.Port{{Proto: "tcp", Port: 80}},
		GuardExes: []string{"/usr/sbin/apache2"},
		GrayUsers: []string{"gray1"},
		DHCP:      true,
		Kill:      true,
		DNS:       config.DNS{Listen: "127.0.0.1:53"},
	}
	log, err := incident.Open(filepath.Join(t.TempDir(), "incidents.jsonl"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	log.OnWrite = func(in incident.Incident) { r.got = append(r.got, in) }
	r.a = &agent{
		cfg: cfg,
		pol: &detect.Policy{
			Cfg:   cfg,
			Gray:  map[uint32]bool{2001: true},
			Self:  selfPID,
			Local: func(netip.Addr) bool { return false },
			Hash:  func(p *proc.Proc) string { return "sum:" + p.Exe },
		},
		log:   log,
		fw:    r.fw,
		now:   func() time.Time { return r.now },
		root:  r.root,
		netns: netns,
		users: map[uint32]string{0: "root", 1000: "alice", 2001: "gray1"},
		logf:  func(string, ...any) {},
		kill: func(pid int, start uint64, protect func(*proc.Proc) bool) ([]int, error) {
			r.kills = append(r.kills, killCall{pid, start, protect})
			if r.killErr != nil {
				return nil, r.killErr
			}
			return append([]int{pid}, r.killed...), nil
		},
		read: func() (*proc.Snapshot, error) {
			r.reads++
			return r.snap, nil
		},
	}
	return r
}

func (r *rig) kind(kind string) []incident.Incident {
	var out []incident.Incident
	for _, in := range r.got {
		if in.Kind == kind {
			out = append(out, in)
		}
	}
	return out
}

func mk(pid, ppid int, uid uint32, exe string) *proc.Proc {
	return &proc.Proc{PID: pid, PPID: ppid, UID: uid, Start: uint64(pid) * 10, Comm: filepath.Base(exe), Exe: exe,
		Cmdline: []string{exe}, NetNS: netns, FDs: map[int]uint64{}}
}

// tree is init, an sshd, the web server, and whatever the test adds.
func tree(extra ...*proc.Proc) *proc.Snapshot {
	s := &proc.Snapshot{Procs: map[int]*proc.Proc{}, Socks: map[string]map[uint64]proc.Sock{netns: {}}}
	for _, p := range append([]*proc.Proc{
		mk(1, 0, 0, "/usr/lib/systemd/systemd"),
		mk(100, 1, 0, "/usr/sbin/sshd"),
		mk(900, 1, 33, "/usr/sbin/apache2"),
	}, extra...) {
		s.Procs[p.PID] = p
	}
	return s
}

var c2 = &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"}

func egress(p *proc.Proc) detect.Detection {
	return detect.Detection{Kind: "egress", PID: p.PID, Start: p.Start, Severity: model.SevHigh, Remote: c2,
		Detail: "connects to 203.0.113.9:4444, which is not allowed out"}
}

func TestHandle_KillWritesIncident(t *testing.T) {
	r := newRig(t)
	x := mk(300, 100, 1000, "/tmp/x")
	x.Cgroup = "/user.slice/user-1000.slice/session-3.scope"
	x.Cmdline = []string{"/tmp/x", "-c", "203.0.113.9"}
	s := tree(x)
	r.a.handle(s, []detect.Detection{egress(x)})
	if len(r.kills) != 1 || r.kills[0].pid != 300 || r.kills[0].start != 3000 {
		t.Fatalf("kills = %+v", r.kills)
	}
	if len(r.got) != 1 {
		t.Fatalf("incidents = %+v", r.got)
	}
	in := r.got[0]
	if in.Kind != "egress" || in.Action != "killed" || in.Severity != model.SevHigh || in.Host != "web01" {
		t.Errorf("incident = %+v", in)
	}
	if in.PID != 300 || in.UID != 1000 || in.User != "alice" || in.Comm != "x" || in.Exe != "/tmp/x" ||
		in.SHA256 != "sum:/tmp/x" || len(in.Cmdline) != 3 || in.Cgroup != x.Cgroup {
		t.Errorf("process fields = %+v", in)
	}
	if in.Remote == nil || *in.Remote != *c2 {
		t.Errorf("remote = %+v", in.Remote)
	}
	if len(in.Chain) != 3 || in.Chain[0].PID != 300 || in.Chain[1].Comm != "sshd" || in.Chain[2].PID != 1 {
		t.Errorf("chain = %+v", in.Chain)
	}
	if in.Origin != "ssh" {
		t.Errorf("origin = %q", in.Origin)
	}
	if in.Time.IsZero() || in.Count != 1 {
		t.Errorf("time %v count %d", in.Time, in.Count)
	}
}

func TestHandle_ContainerNamed(t *testing.T) {
	r := newRig(t)
	x := mk(300, 1, 0, "/bin/busybox")
	x.Cgroup = "/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope"
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(r.got) != 1 || r.got[0].Container != "0123456789ab" || r.got[0].Origin != "container:0123456789ab" {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_KillFalseIsWouldKill(t *testing.T) {
	r := newRig(t)
	r.a.cfg.Kill = false
	x := mk(300, 100, 1000, "/tmp/x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(r.kills) != 0 {
		t.Fatalf("kill called: %+v", r.kills)
	}
	if len(r.got) != 1 || r.got[0].Action != "would-kill" {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_GuardedHeld(t *testing.T) {
	r := newRig(t)
	s := tree()
	r.a.handle(s, []detect.Detection{egress(s.Procs[900])})
	if len(r.kills) != 0 {
		t.Fatalf("kill called on a guarded process: %+v", r.kills)
	}
	if len(r.got) != 1 || r.got[0].Action != "held" || r.got[0].PID != 900 {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_ErrGoneIsAlert(t *testing.T) {
	r := newRig(t)
	r.killErr = respond.ErrGone
	x := mk(300, 100, 1000, "/tmp/x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(r.got) != 1 || r.got[0].Action != "alert" || !strings.HasSuffix(r.got[0].Detail, " (exited)") {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_KillErrorIsKillFailed(t *testing.T) {
	r := newRig(t)
	r.killErr = errors.New("pidfd_open: operation not permitted")
	x := mk(300, 100, 1000, "/tmp/x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(r.got) != 1 || r.got[0].Action != "kill-failed" || !strings.Contains(r.got[0].Detail, "operation not permitted") {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_ExitedProcessIsAlert(t *testing.T) {
	r := newRig(t)
	d := detect.Detection{Kind: "egress", PID: 300, Severity: model.SevHigh, Remote: c2, Detail: "connects to 203.0.113.9:4444 (exited)"}
	r.a.handle(tree(), []detect.Detection{d})
	if len(r.kills) != 0 || len(r.got) != 1 || r.got[0].Action != "alert" || r.got[0].PID != 300 || r.got[0].Exe != "" {
		t.Fatalf("kills %+v incidents %+v", r.kills, r.got)
	}
}

func TestHandle_TwoDetectionsOnePidOneKill(t *testing.T) {
	r := newRig(t)
	x := mk(300, 100, 1000, "/usr/bin/bash")
	shell := detect.Detection{Kind: "revshell-stdio", PID: 300, Start: x.Start, Severity: model.SevCritical, Remote: c2, Detail: "shell on a socket"}
	r.a.handle(tree(x), []detect.Detection{egress(x), shell})
	if len(r.kills) != 1 {
		t.Fatalf("kill called %d times", len(r.kills))
	}
	if len(r.got) != 2 || r.got[0].Kind != "revshell-stdio" || r.got[1].Kind != "egress" ||
		r.got[0].Action != "killed" || r.got[1].Action != "killed" {
		t.Fatalf("incidents = %+v", r.got)
	}
}

// A detection that alone would only alert is logged killed once another
// detection has killed its process.
func TestHandle_AlertOnKilledPidIsKilled(t *testing.T) {
	r := newRig(t)
	x := mk(300, 100, 1000, "/usr/bin/bash")
	shell := detect.Detection{Kind: "revshell-stdio", PID: 300, Start: x.Start, Severity: model.SevCritical, Remote: c2}
	lsn := detect.Detection{Kind: "listener", PID: 300, Start: x.Start, Severity: model.SevLow, NoKill: true, Detail: "listens on tcp 127.0.0.1:9"}
	r.a.handle(tree(x), []detect.Detection{lsn, shell})
	if len(r.kills) != 1 || len(r.got) != 2 || r.got[1].Kind != "listener" || r.got[1].Action != "killed" {
		t.Fatalf("kills %d incidents %+v", len(r.kills), r.got)
	}
}

func TestHandle_KilledDescendantNotKilledAgain(t *testing.T) {
	r := newRig(t)
	x, y := mk(300, 100, 1000, "/tmp/x"), mk(301, 300, 1000, "/tmp/y")
	r.killed = []int{301}
	r.a.handle(tree(x, y), []detect.Detection{egress(x), egress(y)})
	if len(r.kills) != 1 || r.kills[0].pid != 300 {
		t.Fatalf("kills = %+v", r.kills)
	}
	if len(r.got) != 2 || r.got[0].Action != "killed" || r.got[1].Action != "killed" || r.got[1].PID != 301 {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestHandle_ProtectCoversGuardedAndSelf(t *testing.T) {
	r := newRig(t)
	x := mk(300, 100, 1000, "/tmp/x")
	s := tree(x)
	r.a.handle(s, []detect.Detection{egress(x)})
	if len(r.kills) != 1 {
		t.Fatalf("kills = %+v", r.kills)
	}
	protect := r.kills[0].protect
	if !protect(s.Procs[900]) {
		t.Error("a guarded executable is not protected")
	}
	// Seen by the kill's own, later read: a new worker that inherited the
	// scored listener.
	s.Socks[netns][77] = proc.Sock{Inode: 77, Family: unix.AF_INET, Proto: "tcp", Listen: true,
		Local: netip.MustParseAddrPort("0.0.0.0:80")}
	worker := mk(950, 1, 33, "/opt/app/server")
	worker.FDs[4] = 77
	if !protect(worker) {
		t.Error("a holder of a scored listener is not protected")
	}
	if !protect(mk(selfPID, 1, 0, "/usr/local/sbin/xdr")) {
		t.Error("the agent is not protected")
	}
	if protect(x) || protect(mk(301, 300, 1000, "/usr/bin/sleep")) {
		t.Error("an ordinary process is protected")
	}
}

type fakeSource struct{ name string }

func (f fakeSource) Name() string                { return f.name }
func (f fakeSource) Events() <-chan sensor.Event { return nil }
func (f fakeSource) Close() error                { return nil }

func TestRun_FallsBackWhenEBPFFails(t *testing.T) {
	var lines []string
	logf := func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	calls := ""
	ok := func(name string) func() (sensor.Source, error) {
		return func() (sensor.Source, error) { calls += name + " "; return fakeSource{name}, nil }
	}
	bad := func(name string) func() (sensor.Source, error) {
		return func() (sensor.Source, error) { calls += name + " "; return nil, errors.New(name + " refused") }
	}
	for _, tc := range []struct {
		mode           string
		ebpf, procconn func() (sensor.Source, error)
		name, calls    string // name "": no source
		line           string // prefix of the one line logged
	}{
		{"auto", ok("ebpf"), ok("proc"), "ebpf", "ebpf ", "sensor: ebpf"},
		{"", ok("ebpf"), ok("proc"), "ebpf", "ebpf ", "sensor: ebpf"},
		{"auto", bad("ebpf"), ok("proc"), "proc", "ebpf proc ", "sensor: proc (ebpf: ebpf refused)"},
		{"auto", bad("ebpf"), bad("proc"), "", "ebpf proc ", "sensor: none (ebpf: ebpf refused; proc: proc refused)"},
		{"ebpf", bad("ebpf"), ok("proc"), "proc", "ebpf proc ", "sensor: proc (ebpf:"},
		{"proc", ok("ebpf"), ok("proc"), "proc", "proc ", "sensor: proc"},
		{"proc", ok("ebpf"), bad("proc"), "", "proc ", "sensor: none (proc: proc refused)"},
		{"none", ok("ebpf"), ok("proc"), "", "", "sensor: none"},
	} {
		lines, calls = nil, ""
		src := openSensor(tc.mode, tc.ebpf, tc.procconn, logf)
		if tc.name == "" && src != nil || tc.name != "" && (src == nil || src.Name() != tc.name) {
			t.Errorf("%q: source = %v, want %q", tc.mode, src, tc.name)
		}
		if calls != tc.calls {
			t.Errorf("%q: tried %q, want %q", tc.mode, calls, tc.calls)
		}
		if len(lines) != 1 || !strings.HasPrefix(lines[0], tc.line) {
			t.Errorf("%q: logged %q, want one line starting %q", tc.mode, lines, tc.line)
		}
	}
}

func TestGuard_DriftRepairedAndLogged(t *testing.T) {
	r := newRig(t)
	r.a.guard()
	if len(r.fw.applied) != 1 || len(r.kind("fw-drift")) != 0 {
		t.Fatalf("first guard: %d applies, incidents %+v", len(r.fw.applied), r.got)
	}
	r.a.guard()
	if len(r.fw.applied) != 1 {
		t.Fatalf("an unchanged table was applied again")
	}
	r.fw.drift = true
	r.a.guard()
	got := r.kind("fw-drift")
	if len(r.fw.applied) != 2 || len(got) != 1 || got[0].Action != "repaired" || got[0].Severity != model.SevHigh {
		t.Fatalf("%d applies, incidents %+v", len(r.fw.applied), got)
	}
	if r.fw.applied[1].String() != r.fw.applied[0].String() {
		t.Error("the repair applied a different ruleset")
	}
	r.a.guard()
	if len(r.fw.applied) != 2 || len(r.kind("fw-drift")) != 1 {
		t.Fatalf("a repaired table was reported again")
	}
}

func TestGuard_ApplyFailureIsLoggedAndRetried(t *testing.T) {
	r := newRig(t)
	r.fw.err = errors.New("netlink: permission denied")
	r.a.guard()
	got := r.kind("fw-drift")
	if len(got) != 1 || got[0].Action != "alert" || !strings.Contains(got[0].Detail, "permission denied") {
		t.Fatalf("incidents = %+v", r.got)
	}
	r.fw.err = nil
	r.a.guard()
	if len(r.fw.applied) != 2 {
		t.Fatalf("a failed apply was not retried: %d applies", len(r.fw.applied))
	}
	r.a.guard()
	if len(r.fw.applied) != 2 {
		t.Fatalf("applied again after success")
	}
}

func TestGuard_DNSExpiryReappliesWithoutDriftIncident(t *testing.T) {
	r := newRig(t)
	r.a.cfg.DNS.Resolver = netip.MustParseAddr("192.0.2.53")
	r.a.cfg.DNS.Enabled = true
	r.a.cfg.DNS.Expires = r.now.Add(time.Hour)
	mark := fmt.Sprintf("meta mark %#x", fw.DNSMark)
	r.a.guard()
	if len(r.fw.applied) != 1 || !strings.Contains(r.fw.applied[0].String(), mark) {
		t.Fatalf("with the switch on the table has no rule for the stub:\n%v", r.fw.applied)
	}
	r.now = r.now.Add(time.Hour + time.Second)
	r.a.guard()
	if len(r.fw.applied) != 2 {
		t.Fatalf("%d applies after expiry, want 2", len(r.fw.applied))
	}
	if strings.Contains(r.fw.applied[1].String(), mark) {
		t.Error("the stub's rule outlived the switch")
	}
	if got := r.kind("fw-drift"); len(got) != 0 {
		t.Errorf("expiry reported as drift: %+v", got)
	}
}

func TestGuard_ChangedFilesLogged(t *testing.T) {
	r := newRig(t)
	r.a.assert(false) // the start: writes the three files, which is no incident
	r.a.guard()
	if len(r.got) != 0 {
		t.Fatalf("incidents before anything changed: %+v", r.got)
	}
	hosts := filepath.Join(r.root, "etc/hosts")
	if err := os.WriteFile(hosts, []byte("203.0.113.9 updates.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r.a.guard()
	got := r.kind("dns-files")
	if len(got) != 1 || got[0].Action != "repaired" || got[0].Detail != "/etc/hosts" {
		t.Fatalf("incidents = %+v", r.got)
	}
	if b, _ := os.ReadFile(hosts); strings.Contains(string(b), "203.0.113.9") {
		t.Errorf("hosts not repaired: %q", b)
	}
}

// asking is a snapshot with a process holding a UDP socket bound to port.
func asking(pid int, port uint16) *proc.Snapshot {
	p := mk(pid, 100, 1000, "/usr/bin/dig")
	p.FDs[3] = 500
	s := tree(p)
	s.Socks[netns][500] = proc.Sock{Inode: 500, Family: unix.AF_INET, Proto: "udp",
		Local: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}
	return s
}

func query(name string, port uint16, allowed bool) dnsguard.Query {
	return dnsguard.Query{Name: name, Type: 16, Client: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Allowed: allowed}
}

func TestOnQuery_BlockedNameNamesProcess(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	r.a.onQuery(query("c2.example.net", 40001, false))
	if len(r.got) != 1 {
		t.Fatalf("incidents = %+v", r.got)
	}
	in := r.got[0]
	if in.Kind != "dns-query" || in.Action != "alert" || in.Severity != model.SevMedium {
		t.Errorf("incident = %+v", in)
	}
	if in.PID != 555 || in.Exe != "/usr/bin/dig" || in.User != "alice" || in.Origin != "ssh" {
		t.Errorf("asker = %+v", in)
	}
	if in.Detail != "name=c2.example.net type=16" {
		t.Errorf("detail = %q", in.Detail)
	}
}

func TestOnQuery_UnknownAskerStillLogged(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	r.a.onQuery(query("c2.example.net", 40999, false))
	if len(r.got) != 1 || r.got[0].PID != 0 || r.got[0].Detail != "name=c2.example.net type=16" {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestOnQuery_SnapshotAtMost200msOld(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	r.a.onQuery(query("a.example.net", 40001, false))
	r.now = r.now.Add(150 * time.Millisecond)
	r.a.onQuery(query("b.example.net", 40001, false))
	if r.reads != 1 {
		t.Fatalf("%d reads within 200 ms, want 1", r.reads)
	}
	r.now = r.now.Add(100 * time.Millisecond)
	r.snap = asking(777, 40002)
	r.a.onQuery(query("c.example.net", 40002, false))
	if r.reads != 2 || r.got[len(r.got)-1].PID != 777 {
		t.Fatalf("%d reads, last incident %+v", r.reads, r.got[len(r.got)-1])
	}
}

func TestOnQuery_AllowedIsQuiet(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	r.a.onQuery(query("archive.example.com", 40001, true))
	if len(r.got) != 0 {
		t.Fatalf("incidents = %+v", r.got)
	}
}

func TestOnQuery_AllowedButScoredAlerts(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	r.a.onQuery(query("mfzwizlomnxw2idbonsg633omruw4zy.t.example.com", 40001, true))
	if len(r.got) != 1 || r.got[0].Severity != model.SevHigh || r.got[0].PID != 555 ||
		r.got[0].Detail != "name=mfzwizlomnxw2idbonsg633omruw4zy.t.example.com type=16 entropy" {
		t.Fatalf("incidents = %+v", r.got)
	}
}

// A process asking in a burst cannot fill the disk: once it is flagged for
// the burst it gets one line per 10 s.
func TestOnQuery_BurstIsBounded(t *testing.T) {
	r := newRig(t)
	r.snap = asking(555, 40001)
	for i := 0; i < 500; i++ {
		r.a.onQuery(query(fmt.Sprintf("q%d.example.net", i), 40001, false))
	}
	n := len(r.got)
	if n < 21 || n > 22 {
		t.Fatalf("%d lines for 500 queries in a burst", n)
	}
	last := r.got[n-1]
	if last.Severity != model.SevHigh || !strings.HasSuffix(last.Detail, " burst") {
		t.Errorf("burst line = %+v", last)
	}
	r.now = r.now.Add(5 * time.Second)
	for i := 0; i < 30; i++ {
		r.a.onQuery(query(fmt.Sprintf("r%d.example.net", i), 40001, false))
	}
	if len(r.got) != n {
		t.Fatalf("%d more lines inside the 10 s", len(r.got)-n)
	}
	r.now = r.now.Add(6 * time.Second)
	for i := 0; i < 30; i++ {
		r.a.onQuery(query(fmt.Sprintf("s%d.example.net", i), 40001, false))
	}
	if len(r.got) != n+1 {
		t.Fatalf("%d more lines after 10 s, want 1", len(r.got)-n)
	}
}

func TestGrayUIDs(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ngray1:x:2001:2001::/home/gray1:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
	users, gray := accounts(strings.NewReader(passwd), []string{"gray1", "nobody-here"})
	if users[0] != "root" || users[1000] != "alice" || len(gray) != 1 || !gray[2001] {
		t.Fatalf("users %v gray %v", users, gray)
	}
}
