package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/detect"
	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pathenc"
	"xdr/internal/proc"
	"xdr/internal/rules"
)

type fakeFleet struct {
	cached   *rules.Set
	proposed []rules.Rule
	reported []incident.Incident
	hunts    []*hunt.Request
	running  chan struct{}
}

func (f *fakeFleet) Cached() (*rules.Set, error) { return f.cached, nil }
func (f *fakeFleet) Run(ctx context.Context, _ func(*rules.Set), _ func(incident.Incident), _ func(*hunt.Request)) {
	close(f.running)
	<-ctx.Done()
}
func (f *fakeFleet) Propose(rs []rules.Rule)     { f.proposed = append(f.proposed, rs...) }
func (f *fakeFleet) Report(in incident.Incident) { f.reported = append(f.reported, in) }
func (f *fakeFleet) PutHunt(r *hunt.Request)     { f.hunts = append(f.hunts, r) }
func (f *fakeFleet) Offer([]byte) bool           { return false }
func (f *fakeFleet) Envelope() ([]byte, uint64)  { return nil, 0 }

// hexSum is a hash the rig's Hash gives exe, in the form rules accept.
func hexSum(exe string) string {
	s := sha256.Sum256([]byte(exe))
	return hex.EncodeToString(s[:])
}

func fleetRig(t *testing.T) (*rig, *fakeFleet) {
	r := newRig(t)
	f := &fakeFleet{running: make(chan struct{})}
	r.a.fleet = f
	r.a.pol.Hash = func(p *proc.Proc) string { return hexSum(p.Exe) }
	return r, f
}

func TestHandle_KillProposes(t *testing.T) {
	r, f := fleetRig(t)
	x := mk(300, 100, 1000, "/tmp/x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	if len(f.proposed) != 2 || f.proposed[0].Kind != "hash" || f.proposed[0].SHA256 != hexSum("/tmp/x") ||
		f.proposed[1].Kind != "remote" || f.proposed[1].Port != 4444 || f.proposed[0].From != "web01" || f.proposed[0].Seen.IsZero() {
		t.Fatalf("%+v", f.proposed)
	}

	// A base-image binary proposes only the endpoint.
	r, f = fleetRig(t)
	bash := mk(301, 100, 1000, "/usr/bin/bash")
	r.a.pol.Base = &baseline.Baseline{Files: map[string]baseline.FileEntry{pathenc.Encode("/usr/bin/bash"): {SHA256: hexSum("/usr/bin/bash")}}}
	r.a.handle(tree(bash), []detect.Detection{egress(bash)})
	if len(f.proposed) != 1 || f.proposed[0].Kind != "remote" {
		t.Fatalf("baseline: %+v", f.proposed)
	}

	// An alert proposes nothing.
	r, f = fleetRig(t)
	l := mk(302, 1, 0, "/tmp/l")
	r.a.handle(tree(l), []detect.Detection{{Kind: "listener", PID: 302, Start: l.Start, Detail: "listens", NoKill: true}})
	if len(f.proposed) != 0 {
		t.Fatalf("listener: %+v", f.proposed)
	}
}

// A killed process has no /proc/<pid>/exe to hash, so whether it ran a
// base-image binary is settled before the kill.
func TestHandle_BaselineJudgedBeforeKill(t *testing.T) {
	r, f := fleetRig(t)
	bash := mk(301, 100, 1000, "/usr/bin/bash")
	r.a.pol.Base = &baseline.Baseline{Files: map[string]baseline.FileEntry{pathenc.Encode("/usr/bin/bash"): {SHA256: hexSum("/usr/bin/bash")}}}
	r.a.pol.Hash = func(p *proc.Proc) string {
		if len(r.kills) > 0 {
			return ""
		}
		return hexSum(p.Exe)
	}
	r.a.handle(tree(bash), []detect.Detection{egress(bash)})
	if len(r.kills) != 1 || len(f.proposed) != 1 || f.proposed[0].Kind != "remote" {
		t.Fatalf("kills %d, proposed %+v", len(r.kills), f.proposed)
	}
}

func TestSetRules_RefusesProtected(t *testing.T) {
	r, _ := fleetRig(t)
	r.a.baseHash = func(s string) bool { return s == hexSum("/usr/bin/bash") }
	jump := rules.Rule{Kind: "remote", Addr: netip.MustParseAddr("192.0.2.7"), Port: 443, Proto: "tcp", From: "db01"}
	base := rules.Rule{Kind: "hash", SHA256: hexSum("/usr/bin/bash"), From: "db01"}
	good := rules.Rule{Kind: "hash", SHA256: hexSum("/tmp/x"), From: "db01"}
	set := &rules.Set{Version: 3, Rules: []rules.Rule{jump, base, good}}
	for i := range set.Rules {
		set.Rules[i].SetID()
	}
	r.a.setRules(set)
	if n := len(r.kind("rules-refused")); n != 2 {
		t.Fatalf("%d refused: %+v", n, r.got)
	}
	for _, in := range r.kind("rules-refused") {
		if !strings.Contains(in.Detail, "protected address") && !strings.Contains(in.Detail, "baseline hash") {
			t.Errorf("%q", in.Detail)
		}
	}
	ix := r.a.pol.Rules
	if ix == nil || len(ix.Hash) != 1 || ix.Hash[good.SHA256] == nil || len(ix.Remote) != 0 {
		t.Fatalf("%+v", ix)
	}
}

func TestRun_CachedRulesBeforeEtcd(t *testing.T) {
	r, f := fleetRig(t)
	r.a.cfg.Kill = false
	x := mk(300, 100, 1000, "/tmp/implant")
	rule := rules.Rule{Kind: "hash", SHA256: hexSum("/tmp/implant"), From: "db01"}
	rule.SetID()
	f.cached = &rules.Set{Version: 1, Rules: []rules.Rule{rule}}
	r.snap = tree(x)
	ctx, cancel := context.WithCancel(context.Background())
	stop := r.a.startFleet(ctx, f)
	defer func() { cancel(); stop() }()
	r.a.sweep()
	hits := r.kind("rule-hash")
	if len(hits) != 1 || hits[0].Action != "would-kill" || hits[0].PID != 300 {
		t.Fatalf("%+v", r.got)
	}
	select {
	case <-f.running:
	case <-time.After(time.Second):
		t.Fatal("the client was not started")
	}
}

func TestRecord_Reports(t *testing.T) {
	r, f := fleetRig(t)
	x := mk(300, 100, 1000, "/tmp/x")
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	r.a.recordLocked(incident.Incident{Kind: "fleet", Action: "alert", Detail: "etcd unreachable"})
	if len(f.reported) != 2 || f.reported[0].Kind != "egress" || f.reported[0].Host != "web01" || f.reported[1].Kind != "fleet" {
		t.Fatalf("%+v", f.reported)
	}
}

func TestReload_RevalidatesRules(t *testing.T) {
	r, _ := fleetRig(t)
	rule := rules.Rule{Kind: "remote", Addr: netip.MustParseAddr("198.51.100.9"), Port: 443, Proto: "tcp", From: "db01"}
	rule.SetID()
	r.a.setRules(&rules.Set{Version: 1, Rules: []rules.Rule{rule}})
	if len(r.a.pol.Rules.Remote) != 1 {
		t.Fatal("rule not taken")
	}
	next := *r.a.cfg
	next.AllowOut = []config.Dest{{To: pfx("198.51.100.0/24"), Proto: "tcp", Port: 443}}
	if err := r.a.reload(&next); err != nil {
		t.Fatal(err)
	}
	if len(r.a.pol.Rules.Remote) != 0 || len(r.kind("rules-refused")) != 1 {
		t.Fatalf("after reload: %+v %+v", r.a.pol.Rules, r.got)
	}
}

// A container's shell killed for a reverse shell proposes only the
// endpoint: its hash is the image's own shell.
func TestHandle_ContainerShellNoHash(t *testing.T) {
	r, f := fleetRig(t)
	sh := mk(301, 100, 1000, "/bin/sh")
	sh.Cgroup = "0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope"
	r.a.handle(tree(sh), []detect.Detection{egress(sh)})
	if len(f.proposed) != 1 || f.proposed[0].Kind != "remote" {
		t.Fatalf("%+v", f.proposed)
	}
}

// No rule may name the agent's own binary.
func TestSetRules_RefusesSelfHash(t *testing.T) {
	r, _ := fleetRig(t)
	r.a.selfHash = hexSum("/usr/local/sbin/xdr")
	self := rules.Rule{Kind: "hash", SHA256: hexSum("/usr/local/sbin/xdr"), From: "db01"}
	self.SetID()
	r.a.setRules(&rules.Set{Version: 1, Rules: []rules.Rule{self}})
	if n := len(r.kind("rules-refused")); n != 1 || len(r.a.pol.Rules.Hash) != 0 {
		t.Fatalf("%d refused, %+v", n, r.a.pol.Rules)
	}
}

// A reverse shell started by a crontab line proposes its parent and that
// line, as well as its hash.
func TestHandle_ProposesNarrowRules(t *testing.T) {
	r, f := fleetRig(t)
	cron := mk(50, 1, 0, "/usr/sbin/cron")
	sh := mk(150, 50, 0, "/usr/bin/dash")
	sh.Cmdline = []string{"/bin/sh", "-c", "/opt/app/srv"}
	srv := mk(200, 150, 0, "/opt/app/srv")
	x := mk(301, 200, 0, "/usr/bin/dash")
	r.a.handle(tree(cron, sh, srv, x), []detect.Detection{{Kind: "revshell-stdio", PID: 301, Start: x.Start, Severity: model.SevCritical, Remote: c2, Detail: "stdio on a socket"}})
	got := map[string]rules.Rule{}
	for _, p := range f.proposed {
		got[p.Kind] = p
	}
	if got["hash"].SHA256 != hexSum("/usr/bin/dash") || got["parent"].ParentExe != "/opt/app/srv" || got["parent"].Exe != "/usr/bin/dash" ||
		got["cron"].Command != "/opt/app/srv" || len(r.kills) != 1 {
		t.Fatalf("kills %d, proposed %+v", len(r.kills), f.proposed)
	}
	if in := r.kind("revshell-stdio"); len(in) != 1 || in[0].Cron != "/opt/app/srv" {
		t.Fatalf("%+v", in)
	}
}

// The file behind a unit: origin is named, and its hash kept only when it
// is not a base-image hash.
func TestDescribe_UnitOrigin(t *testing.T) {
	r, _ := fleetRig(t)
	unit := "[Service]\nExecStart=/tmp/x\n"
	if err := os.MkdirAll(filepath.Join(r.root, "etc/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, "etc/systemd/system/evil.service"), []byte(unit), 0o644); err != nil {
		t.Fatal(err)
	}
	x := mk(300, 1, 0, "/tmp/x")
	x.Cgroup = "/system.slice/evil.service"
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	in := r.kind("egress")
	if len(in) != 1 || in[0].Origin != "unit:evil.service" || in[0].OriginFile != "/etc/systemd/system/evil.service" || in[0].OriginSHA256 != hexSum(unit) {
		t.Fatalf("%+v", in)
	}
	r.got = nil
	r.a.baseHash = func(s string) bool { return s == hexSum(unit) }
	x2 := mk(310, 1, 0, "/tmp/x")
	x2.Cgroup = x.Cgroup
	r.a.handle(tree(x2), []detect.Detection{egress(x2)})
	if in := r.kind("egress"); len(in) != 1 || in[0].OriginFile == "" || in[0].OriginSHA256 != "" {
		t.Fatalf("baseline unit: %+v", in)
	}
}

// A shell killed inside a scored service's unit names no unit origin: a
// unit rule or indicator would take the service down fleet-wide.
func TestDescribe_ScoredUnitNotOrigin(t *testing.T) {
	r, f := fleetRig(t)
	if err := os.MkdirAll(filepath.Join(r.root, "etc/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.root, "etc/systemd/system/webapp.service"), []byte("[Service]\nExecStart=/usr/sbin/apache2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := mk(200, 1, 33, "/usr/sbin/apache2")
	x := mk(300, 200, 33, "/tmp/x")
	srv.Cgroup, x.Cgroup = "/system.slice/webapp.service", "/system.slice/webapp.service"
	r.a.handle(tree(srv, x), []detect.Detection{egress(x)})
	in := r.kind("egress")
	if len(in) != 1 || in[0].OriginFile == "" || in[0].OriginSHA256 != "" {
		t.Fatalf("%+v", in)
	}
	for _, p := range f.proposed {
		if p.Kind == "unit" {
			t.Fatalf("unit rule proposed: %+v", p)
		}
	}
}
