// Package agent runs the firewall, the DNS guard, the sensors and the
// response on one box.
package agent

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/config"
	"xdr/internal/detect"
	"xdr/internal/dnsguard"
	"xdr/internal/fleet"
	"xdr/internal/fw"
	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/persist"
	"xdr/internal/proc"
	"xdr/internal/respond"
	"xdr/internal/rules"
	"xdr/internal/sensor"
)

const (
	sweepEvery  = time.Second
	guardEvery  = 3 * time.Second
	foldWindow  = 60 * time.Second
	snapMaxAge  = 200 * time.Millisecond
	rereadEvery = 25 * time.Millisecond // at most this often for a query with no owner // how old a snapshot may be to name a DNS asker
	eventDelay  = 50 * time.Millisecond // events are gathered this long, then judged on one snapshot
	maxPending  = 4096
	burstWindow = 10 * time.Second
	askerTimes  = 32 // query times kept per asker; a burst is more than 20

	procRoot   = "/proc"
	cgroupRoot = "/sys/fs/cgroup"
	defaultLog = "/var/lib/xdr/incidents.jsonl"
)

// Options configures Run.
type Options struct {
	ConfigPath string
	Baselines  []string                // extra layers over the embedded one
	Sensor     string                  // "auto" (default) | "ebpf" | "proc" | "none"
	LogPath    string                  // default /var/lib/xdr/incidents.jsonl
	Stderr     io.Writer               // sensor and reload messages
	OnIncident func(incident.Incident) // called for every line written
}

// fleetLink is the agent's link to the controller (fleet.Client).
type fleetLink interface {
	Cached() (*rules.Set, error)
	Run(ctx context.Context, onRules func(*rules.Set), onIncident func(incident.Incident), onHunt func(*hunt.Request))
	Propose([]rules.Rule)
	Report(incident.Incident)
	PutHunt(*hunt.Request)
	Offer([]byte) bool
	Envelope() ([]byte, uint64)
}

type firewall interface {
	Apply(fw.Ruleset) error
	Drifted() (bool, error)
	Foreign() ([]fw.BaseChain, error)
}

// asker is one process's recent DNS queries.
type asker struct {
	times   []time.Time
	flagged time.Time // when a line was last written for its burst
}

type agent struct {
	mu  sync.Mutex // handle, guard and onQuery run one at a time
	cfg *config.Config
	pol *detect.Policy
	log *incident.Log
	fw  firewall

	kill  func(pid int, start uint64, protect func(*proc.Proc) bool) ([]int, error)
	read  func() (*proc.Snapshot, error)
	now   func() time.Time
	root  string // "/": where etc lives
	netns string // the agent's own network namespace, where the stub listens
	users map[uint32]string
	logf  func(string, ...any)

	applied string          // the ruleset last applied, as text
	pinned  string          // the config and DNS switch the files were last asserted for
	foreign map[string]bool // base chains of other tables already seen (nil: not looked yet)

	fleet    fleetLink // nil: a standalone agent
	mesh     meshLink  // nil: no peer links
	hunts    *hunter   // nil: no hunts run here
	search   func(context.Context, *hunt.Request) hunt.Result
	baseHash func(string) bool      // a hash of the baseline; nil: none
	selfHash string                 // this binary's hash; "": unknown
	ruleSet  *rules.Set             // the last verified set, before the agent's own check
	exeSize  func(*proc.Proc) int64 // nil: unknown
	snap     *proc.Snapshot
	snapAt   time.Time

	unitMu sync.Mutex
	units  map[string]string // unit → unit file hash, this sweep
	askers map[int]*asker
}

// accounts reads passwd: the name of each uid, and the uids of the gray
// accounts.
func accounts(r io.Reader, gray []string) (users map[uint32]string, grayUIDs map[uint32]bool) {
	users, grayUIDs = map[uint32]string{}, map[uint32]bool{}
	for _, a := range collect.ParsePasswd(r) {
		if a.Bad {
			continue
		}
		if _, ok := users[a.UID]; !ok {
			users[a.UID] = a.Name
		}
		if slices.Contains(gray, a.Name) {
			grayUIDs[a.UID] = true
		}
	}
	return users, grayUIDs
}

// setConfig takes cfg into use, keeping everything else of the policy.
func (a *agent) setConfig(cfg *config.Config) {
	passwd, err := collect.ReadFile(filepath.Join(a.root, "etc/passwd"), 1<<20)
	if err != nil {
		a.logf("passwd: %v", err)
	}
	users, gray := accounts(bytes.NewReader(passwd), cfg.GrayUsers)
	a.mu.Lock()
	defer a.mu.Unlock()
	pol := *a.pol
	pol.Cfg, pol.Gray = cfg, gray
	a.cfg, a.pol, a.users = cfg, &pol, users
}

// reload takes a reloaded config into use, unless it moves the DNS stub
// (which stays bound where it started) or changes who can reach the box: the agent applies a table at once and keeps it, with no
// trial and no revert, so a wrong address there would be a lockout. Such a
// change needs a restart, after `xdr fw try` with the new file for an
// access change.
func (a *agent) reload(cfg *config.Config) error {
	a.mu.Lock()
	old := a.cfg
	a.mu.Unlock()
	var changed []string
	if !slices.Equal(old.Jump, cfg.Jump) {
		changed = append(changed, "jump")
	}
	if !slices.Equal(old.SSHFrom, cfg.SSHFrom) {
		changed = append(changed, "ssh_from")
	}
	if old.SSHPort != cfg.SSHPort {
		changed = append(changed, "ssh_port")
	}
	if !slices.Equal(old.XDRPorts, cfg.XDRPorts) {
		changed = append(changed, "xdr_ports")
	}
	if old.DNS.Listen != cfg.DNS.Listen {
		changed = append(changed, "dns.listen") // the stub stays bound where it is
	}
	if !reflect.DeepEqual(old.Fleet, cfg.Fleet) || old.RulesCache != cfg.RulesCache {
		changed = append(changed, "fleet") // the client is started once
	}
	if changed != nil {
		return fmt.Errorf("%s changed; restart the agent for that, after `xdr fw try`", strings.Join(changed, ", "))
	}
	a.setConfig(cfg)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.takeRules() // what is protected may have changed
	return nil
}

// setRules takes a verified rule set into use.
func (a *agent) setRules(s *rules.Set) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ruleSet = s
	a.takeRules()
}

// takeRules checks the rules of the set in force against this box's own
// config, as the controller did against the fleet's, and enforces those
// that pass. The caller holds a.mu.
func (a *agent) takeRules() {
	if a.ruleSet == nil {
		return
	}
	// Whatever the baselines say, this binary is never a hash rule.
	baseHash := func(s string) bool { return s == a.selfHash || a.baseHash != nil && a.baseHash(s) }
	if a.selfHash == "" {
		baseHash = a.baseHash
	}
	g := rules.Guard{Baseline: baseHash, GuardExes: a.cfg.GuardExes, Protect: a.cfg.Protected(),
		StockCron: persist.StockCron(a.root, a.baseHash)}
	var kept []rules.Rule
	for _, r := range a.ruleSet.Rules {
		if err := g.Validate(r); err != nil {
			a.record(incident.Incident{Kind: "rules-refused", Action: "alert", Severity: model.SevHigh,
				Detail: fmt.Sprintf("rule %s from %s, version %d: %v", r.ID, r.From, a.ruleSet.Version, err)})
			continue
		}
		kept = append(kept, r)
	}
	ix := (&rules.Set{Rules: kept}).Lookup()
	pol := *a.pol
	pol.Rules = &ix
	a.pol = &pol
}

// recordLocked is record for callers that do not hold a.mu.
func (a *agent) recordLocked(in incident.Incident) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.record(in)
}

// startFleet enforces the cached rule set, then starts f. stop waits for
// it after ctx is done.
func (a *agent) startFleet(ctx context.Context, f fleetLink) (stop func()) {
	a.fleet = f
	if s, err := f.Cached(); err != nil {
		a.recordLocked(incident.Incident{Kind: "rules-refused", Action: "alert", Severity: model.SevHigh, Detail: "cached rule set: " + err.Error()})
	} else if s != nil {
		a.setRules(s)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.Run(ctx, func(s *rules.Set) {
			a.setRules(s)
			if a.mesh != nil {
				a.mesh.PushRules()
			}
		}, a.recordLocked, func(r *hunt.Request) {
			a.offerHunt(r, "etcd")
			// A peer cut off from etcd hears it this way.
			if a.mesh != nil {
				a.mesh.PushHunt(r, netip.Addr{})
			}
		})
	}()
	return func() { <-done }
}

// async returns fn run on its own goroutine behind a queue of n: the
// returned function never blocks, and drops what does not fit. stop waits
// for the queue to drain; a call after stop is dropped.
func async(fn func(incident.Incident), n int) (call func(incident.Incident), stop func()) {
	q := make(chan incident.Incident, n)
	done := make(chan struct{})
	var mu sync.Mutex
	closed := false
	go func() {
		defer close(done)
		for in := range q {
			fn(in)
		}
	}()
	call = func(in incident.Incident) {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return
		}
		select {
		case q <- in:
		default:
		}
	}
	stop = func() {
		mu.Lock()
		if !closed {
			closed = true
			close(q)
		}
		mu.Unlock()
		<-done
	}
	return call, stop
}

// record writes one incident.
func (a *agent) record(in incident.Incident) {
	in.Host = a.cfg.Host
	if in.Time.IsZero() {
		in.Time = a.now()
	}
	if _, err := a.log.Add(in); err != nil {
		a.logf("incident log: %v", err)
	}
	if a.fleet != nil {
		a.fleet.Report(in)
	}
}

// describe fills in what is known about the process an incident is about.
func (a *agent) describe(in *incident.Incident, s *proc.Snapshot, p *proc.Proc) {
	in.PID, in.UID, in.User = p.PID, p.UID, a.users[p.UID]
	in.Comm, in.Exe, in.Cmdline, in.Cgroup = p.Comm, p.Exe, p.Cmdline, p.Cgroup
	if a.pol.Hash != nil {
		in.SHA256 = a.pol.Hash(p)
	}
	chain := s.Chain(p.PID)
	for _, c := range chain {
		in.Chain = append(in.Chain, incident.ProcRef{PID: c.PID, Comm: c.Comm, Exe: c.Exe})
	}
	in.Container, in.Origin = proc.Container(p.Cgroup), proc.Origin(chain)
	if u, ok := strings.CutPrefix(in.Origin, "unit:"); ok {
		if file, sum, err := persist.UnitFile(a.root, u); err == nil {
			in.OriginFile = file
			// A scored service's unit, or a base-image one, is no
			// indicator: a rule on it would take the service down.
			if (a.baseHash == nil || !a.baseHash(sum)) && !a.pol.ServiceUnit(s, u) {
				in.OriginSHA256 = sum
			}
		}
	}
	in.Cron = persist.CronCommand(chain)
	if a.exeSize != nil {
		in.Size = a.exeSize(p)
	}
}

// unitHash is the hash of the file behind unit, kept for the sweep.
func (a *agent) unitHash(unit string) string {
	a.unitMu.Lock()
	defer a.unitMu.Unlock()
	if sum, ok := a.units[unit]; ok {
		return sum
	}
	_, sum, _ := persist.UnitFile(a.root, unit)
	if a.units == nil {
		a.units = map[string]string{}
	}
	a.units[unit] = sum
	return sum
}

// handle responds to the detections made on snapshot s and logs each.
func (a *agent) handle(s *proc.Snapshot, ds []detect.Detection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// One process's detections together, the most severe first: that is
	// the one the kill is logged under.
	first := map[int]int{}
	for i, d := range ds {
		if _, ok := first[d.PID]; !ok {
			first[d.PID] = i
		}
	}
	ds = slices.Clone(ds)
	slices.SortStableFunc(ds, func(x, y detect.Detection) int {
		if x.PID != y.PID {
			return cmp.Compare(first[x.PID], first[y.PID])
		}
		return cmp.Compare(y.Severity, x.Severity)
	})
	protect := func(p *proc.Proc) bool { return p.PID == a.pol.Self || a.pol.Guarded(s, p) }
	killed := map[int]bool{}
	for _, d := range ds {
		in := incident.Incident{Kind: d.Kind, Severity: d.Severity, PID: d.PID, Remote: d.Remote, Detail: d.Detail}
		// Settled now: once killed, the process has no exe left to hash. A
		// container's shells and interpreters count as base-image too.
		base := false
		if p := s.Procs[d.PID]; p != nil && p.Start == d.Start {
			a.describe(&in, s, p)
			base = a.fleet != nil && (a.pol.Baseline(p) || detect.Class(p) != "" && proc.Container(p.Cgroup) != "")
		}
		switch decided := respond.Decide(d, s, a.pol); {
		case killed[d.PID]:
			in.Action = "killed" // with its process, by an earlier detection
		case decided != "kill":
			in.Action = decided
		case !a.cfg.Kill:
			in.Action = "would-kill"
		default:
			pids, err := a.kill(d.PID, d.Start, protect)
			for _, pid := range pids {
				killed[pid] = true
			}
			switch {
			case err == nil:
				in.Action = "killed"
			case slices.Contains(pids, d.PID):
				in.Action, in.Detail = "killed", in.Detail+" ("+err.Error()+")"
			case errors.Is(err, respond.ErrGone):
				in.Action, in.Detail = "alert", in.Detail+" (exited)"
			case errors.Is(err, respond.ErrSpared):
				in.Action, in.Detail = "alert", in.Detail+" (protected: not killed)"
			default:
				in.Action, in.Detail = "kill-failed", in.Detail+": "+err.Error()
			}
		}
		a.record(in)
		if a.fleet != nil {
			in.Host, in.Time = a.cfg.Host, a.now()
			a.fleet.Propose(rules.FromIncident(in, base))
			a.startHunt(in, base)
		}
	}
}

// guard keeps the firewall table and the pinned DNS files as the config
// has them.
func (a *agent) guard() { a.assert(true) }

// assert is guard; with report false, files it had to write are not
// incidents (the first run on a box writes all of them).
func (a *agent) assert(report bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	drift := func(action, detail string) {
		a.record(incident.Incident{Kind: "fw-drift", Action: action, Severity: model.SevHigh, Detail: detail})
	}
	rules := fw.Build(a.cfg, now)
	if text := rules.String(); text != a.applied {
		// The DNS switch, its expiry or a reload: ours, not drift.
		if err := a.fw.Apply(rules); err != nil {
			drift("alert", "the table could not be applied: "+err.Error())
		} else {
			a.applied = text
		}
	} else if drifted, err := a.fw.Drifted(); err != nil {
		drift("alert", "the table could not be read: "+err.Error())
	} else if drifted {
		if err := a.fw.Apply(rules); err != nil {
			drift("alert", "the table was changed and could not be repaired: "+err.Error())
		} else {
			drift("repaired", "table inet xdr was changed")
		}
	}
	// A reload or the switch going on or off changes the files the
	// config calls for: writing them then is not a repair.
	pinned := fmt.Sprintf("%p %v", a.cfg, a.cfg.DNSOn(now))
	report = report && pinned == a.pinned
	changed, err := dnsguard.Assert(a.root, a.cfg, now)
	if err == nil {
		a.pinned = pinned
	}
	for _, path := range changed {
		if report {
			a.record(incident.Incident{Kind: "dns-files", Action: "repaired", Severity: model.SevMedium, Detail: path})
		} else {
			a.logf("dns: wrote %s", path)
		}
	}
	if err != nil {
		a.record(incident.Incident{Kind: "dns-files", Action: "alert", Severity: model.SevMedium, Detail: err.Error()})
	}
	a.checkForeign()
}

// checkForeign reports base chains of other tables: one that appears after
// start (those there at start are the box's own, Docker's nat), and a nat
// chain on output after ours at any time, since it can send what our table
// let out somewhere else. Each is reported once.
func (a *agent) checkForeign() {
	chains, err := a.fw.Foreign()
	if err != nil {
		return // the table check above reports an unreachable nftables
	}
	first := a.foreign == nil
	if first {
		a.foreign = map[string]bool{}
	}
	for _, b := range chains {
		desc := b.String()
		if a.foreign[desc] {
			continue
		}
		a.foreign[desc] = true
		switch {
		case b.Late():
			a.record(incident.Incident{Kind: "fw-foreign", Action: "alert", Severity: model.SevHigh,
				Detail: "nat on output after the xdr filter can redirect what it lets out: " + desc})
		case !first:
			a.record(incident.Incident{Kind: "fw-foreign", Action: "alert", Severity: model.SevHigh,
				Detail: "base chain appeared: " + desc})
		}
	}
}

// fresh reads proc again unless the last snapshot is younger than
// snapMaxAge. It returns the last snapshot when proc cannot be read. The
// caller holds mu.
func (a *agent) fresh(now time.Time, force bool) *proc.Snapshot {
	if force || a.snap == nil || now.Sub(a.snapAt) > snapMaxAge {
		if s, err := a.read(); err == nil {
			a.snap, a.snapAt = s, now
		}
	}
	return a.snap
}

// onQuery judges one DNS query. The stub calls it before it replies, so
// the asker's socket is still there to be found.
func (a *agent) onQuery(q dnsguard.Query) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	var owner *proc.Proc
	s := a.fresh(now, false)
	if s != nil {
		owner = s.UDPOwner(a.netns, q.Client.Port())
	}
	if owner == nil && now.Sub(a.snapAt) >= rereadEvery {
		// The asker's socket may be younger than the snapshot. A flood of
		// queries nobody owns costs one read per rereadEvery, not one each.
		if s = a.fresh(now, true); s != nil {
			owner = s.UDPOwner(a.netns, q.Client.Port())
		}
	}
	pid := 0
	if owner != nil {
		pid = owner.PID
	}
	if a.askers == nil {
		a.askers = map[int]*asker{}
	}
	ask := a.askers[pid]
	if ask == nil {
		ask = &asker{}
		a.askers[pid] = ask
	}
	ask.times = slices.DeleteFunc(ask.times, func(t time.Time) bool { return now.Sub(t) >= burstWindow })
	recent := len(ask.times)
	if len(ask.times) == askerTimes {
		ask.times = ask.times[1:]
	}
	ask.times = append(ask.times, now)

	points, reasons := dnsguard.Score(q.Name, recent)
	if q.Allowed && points < 3 {
		return
	}
	if slices.Contains(reasons, "burst") {
		// Every name of a tunnel is new, so the log cannot fold them:
		// a process in a burst gets one line per window.
		if !ask.flagged.IsZero() && now.Sub(ask.flagged) < burstWindow {
			return
		}
		ask.flagged = now
	}
	in := incident.Incident{Kind: "dns-query", Action: "alert", Severity: model.SevMedium,
		Detail: strings.TrimSpace(fmt.Sprintf("name=%s type=%d %s", q.Name, q.Type, strings.Join(reasons, ",")))}
	if points >= 3 {
		in.Severity = model.SevHigh
	}
	if owner != nil {
		a.describe(&in, s, owner)
	}
	a.record(in)
}

// take reads a new snapshot and keeps it for onQuery.
func (a *agent) take() (*proc.Snapshot, *detect.Policy, error) {
	s, err := a.read()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	a.snap, a.snapAt = s, a.now()
	a.unitMu.Lock()
	a.units = nil
	a.unitMu.Unlock()
	for pid, ask := range a.askers {
		if n := len(ask.times); n == 0 || a.snapAt.Sub(ask.times[n-1]) >= burstWindow {
			delete(a.askers, pid)
		}
	}
	return s, a.pol, nil
}

// sweep judges every process.
func (a *agent) sweep() {
	s, pol, err := a.take()
	if err != nil {
		a.logf("sweep: %v", err)
		return
	}
	a.handle(s, detect.Sweep(s, pol))
}

// wanted reports whether an event needs a look at the process behind it.
func (a *agent) wanted(ev sensor.Event) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch ev.Kind {
	case sensor.Connect, sensor.Send:
		return !a.pol.AllowedOut(ev.Dst, ev.Proto)
	}
	return true
}

// onEvents judges a batch of sensor events on one new snapshot.
func (a *agent) onEvents(evs []sensor.Event) {
	s, pol, err := a.take()
	if err != nil {
		a.logf("events: %v", err)
		return
	}
	var ds []detect.Detection
	for _, ev := range evs {
		ds = append(ds, detect.Event(ev, s, pol)...)
	}
	a.handle(s, ds)
}

// openSensor opens the event source mode asks for, falling back from eBPF
// to the proc connector to none (the sweep alone), and logs one line
// saying which is in use.
func openSensor(mode string, ebpf, procconn func() (sensor.Source, error), logf func(string, ...any)) sensor.Source {
	var failed []string
	try := func(name string, open func() (sensor.Source, error)) sensor.Source {
		src, err := open()
		if err != nil {
			failed = append(failed, name+": "+err.Error())
			return nil
		}
		return src
	}
	why := func() string {
		if failed == nil {
			return ""
		}
		return " (" + strings.Join(failed, "; ") + ")"
	}
	if mode == "none" {
		logf("sensor: none (switched off)")
		return nil
	}
	if mode != "proc" {
		if src := try("ebpf", ebpf); src != nil {
			logf("sensor: ebpf")
			return src
		}
	}
	if src := try("proc", procconn); src != nil {
		logf("sensor: proc%s", why())
		return src
	}
	logf("sensor: none%s", why())
	return nil
}

func localAddrs() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out[ip.Unmap()] = true
			}
		}
	}
	return out
}

// Run is the agent: it loads the firewall, pins name resolution, serves
// the DNS stub, and watches and judges processes until ctx is done or it
// is told to stop (SIGTERM, SIGINT). SIGHUP reloads the config. The
// firewall table and the pinned files stay when it returns.
func Run(ctx context.Context, o Options) error {
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.LogPath == "" {
		o.LogPath = defaultLog
	}
	logf := func(format string, args ...any) { fmt.Fprintf(o.Stderr, format+"\n", args...) }
	cfg, err := config.Load(o.ConfigPath)
	if err != nil {
		return err
	}
	base, err := baseline.LoadLayers(o.Baselines)
	if err != nil {
		return err
	}
	table, err := fw.Open()
	if err != nil {
		return err
	}
	defer table.Close()
	log, err := incident.Open(o.LogPath, foldWindow)
	if err != nil {
		return err
	}
	defer log.Close()
	if o.OnIncident != nil {
		onWrite, stop := async(o.OnIncident, 256)
		defer stop()
		log.OnWrite = onWrite
	}

	var local atomic.Pointer[map[netip.Addr]bool]
	addrs := localAddrs()
	local.Store(&addrs)
	netns, _ := os.Readlink(procRoot + "/self/ns/net")
	a := &agent{
		pol: &detect.Policy{
			Base:  base,
			Self:  os.Getpid(),
			Local: func(ip netip.Addr) bool { return (*local.Load())[ip.Unmap()] },
			Hash:  func(p *proc.Proc) string { sum, _ := proc.ExeHash(procRoot, p); return sum },
		},
		log: log,
		fw:  table,
		kill: func(pid int, start uint64, protect func(*proc.Proc) bool) ([]int, error) {
			return respond.KillTree(procRoot, pid, start, protect)
		},
		read:  func() (*proc.Snapshot, error) { return proc.Read(procRoot) },
		now:   time.Now,
		root:  "/",
		netns: netns,
		logf:  logf,
	}
	a.exeSize = func(p *proc.Proc) int64 {
		st, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(p.PID), "exe"))
		if err != nil {
			return 0
		}
		return st.Size()
	}
	a.pol.UnitHash = a.unitHash
	a.setConfig(cfg)
	a.baseHash = rules.BaselineHashes(base)
	a.selfHash, _ = proc.ExeHash(procRoot, &proc.Proc{PID: os.Getpid()})

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if cfg.Fleet != nil {
		// Without its keys the agent still enforces on its own.
		if pub, err := rules.LoadPublic(filepath.Join(cfg.Fleet.Dir, "rules.pub")); err != nil {
			a.recordLocked(incident.Incident{Kind: "fleet", Action: "alert", Severity: model.SevHigh, Detail: "not joining the fleet: " + err.Error()})
		} else {
			fctx, cancel := context.WithCancel(ctx)
			fl := fleet.New(cfg.Host, *cfg.Fleet, cfg.RulesCache, pub)
			defer a.startHunts(fctx)()
			runMesh := func() {}
			if cfg.Mesh != nil {
				runMesh = a.newMesh(fctx, cfg, fl)
			}
			wait := a.startFleet(fctx, fl)
			defer wait()
			runMesh()
			defer cancel()
		}
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	a.assert(false)

	var stub sync.WaitGroup
	defer stub.Wait()
	if pc, err := net.ListenPacket("udp", cfg.DNS.Listen); err != nil {
		a.mu.Lock()
		a.record(incident.Incident{Kind: "dns-stub", Action: "alert", Severity: model.SevHigh, Detail: err.Error()})
		a.mu.Unlock()
	} else {
		defer pc.Close()
		srv := &dnsguard.Stub{
			Allowed: func(name string) bool {
				a.mu.Lock()
				defer a.mu.Unlock()
				return a.cfg.DNSOn(a.now()) && slices.Contains(a.cfg.DNS.Allow, name)
			},
			Upstream: func(ctx context.Context, q []byte) ([]byte, error) {
				a.mu.Lock()
				resolver := a.cfg.DNS.Resolver
				a.mu.Unlock()
				return dnsguard.MarkedUpstream(resolver)(ctx, q)
			},
			OnQuery: a.onQuery,
		}
		stub.Add(1)
		go func() {
			defer stub.Done()
			if err := srv.Serve(ctx, pc); err != nil {
				a.mu.Lock()
				a.record(incident.Incident{Kind: "dns-stub", Action: "alert", Severity: model.SevHigh, Detail: err.Error()})
				a.mu.Unlock()
			}
		}()
	}

	var events <-chan sensor.Event
	src := openSensor(o.Sensor,
		func() (sensor.Source, error) { return sensor.NewEBPF(cgroupRoot) },
		sensor.NewProcConn, logf)
	if src != nil {
		defer src.Close()
		events = src.Events()
	}

	a.sweep()
	sweeps, guards := time.NewTicker(sweepEvery), time.NewTicker(guardEvery)
	defer sweeps.Stop()
	defer guards.Stop()
	var pending []sensor.Event
	var flush <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-hup:
			cfg, err := config.Load(o.ConfigPath)
			if err != nil {
				logf("reload: %v; the old config stays", err)
				continue
			}
			if err := a.reload(cfg); err != nil {
				logf("reload: %v; the old config stays", err)
				continue
			}
			a.guard()
			logf("reload: done")
		case <-sweeps.C:
			a.sweep()
		case <-guards.C:
			addrs := localAddrs()
			local.Store(&addrs)
			a.guard()
		case ev, ok := <-events:
			if !ok {
				events = nil
				logf("sensor: %s stopped; sweeping only", src.Name())
				continue
			}
			if !a.wanted(ev) || len(pending) >= maxPending {
				continue
			}
			pending = append(pending, ev)
			if flush == nil {
				flush = time.After(eventDelay)
			}
		case <-flush:
			a.onEvents(pending)
			pending, flush = nil, nil
		}
	}
}
