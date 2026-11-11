package detect

import (
	"net/netip"
	"strings"
	"testing"

	"xdr/internal/model"
	"xdr/internal/rules"
	"xdr/internal/sensor"
)

func withRules(p *Policy, rs ...rules.Rule) *Policy {
	for i := range rs {
		rs[i].SetID()
	}
	ix := (&rules.Set{Rules: rs}).Lookup()
	p.Rules = &ix
	return p
}

var c2Rule = rules.Rule{Kind: "remote", Addr: netip.MustParseAddr("203.0.113.9"), Port: 4444, Proto: "tcp", From: "db01", Detail: "egress: blocked"}

func TestRules_HashHit(t *testing.T) {
	hashes["/tmp/implant"] = "ff"
	defer delete(hashes, "/tmp/implant")
	p := withRules(pol(), rules.Rule{Kind: "hash", SHA256: "ff", From: "db01", Detail: "egress: x"})
	ds := only(Sweep(snap(append(web(), mk(10, 1, "/tmp/implant", nil))), p), "rule-hash")
	want(t, ds, "rule-hash:10")
	if d := ds[0]; d.Severity != model.SevCritical || d.Start != 1010 || !strings.HasPrefix(d.Detail, "rule ") || !strings.Contains(d.Detail, " from db01: egress: x") {
		t.Fatalf("%+v", d)
	}
	ds = Event(sensor.Event{Kind: sensor.Exec, PID: 10, Filename: "/tmp/implant"}, snap(append(web(), mk(10, 1, "/tmp/implant", nil))), p)
	want(t, only(ds, "rule-hash"), "rule-hash:10")
}

func TestRules_RemoteHit(t *testing.T) {
	http := lsn(80, "tcp", "0.0.0.0:80")
	for name, c := range map[string]struct {
		sock string // local, remote
		want []string
	}{
		"connected to the c2":         {"192.0.2.5:40000 203.0.113.9:4444", []string{"rule-remote:10"}},
		"mapped c2":                   {"[::ffff:192.0.2.5]:40000 [::ffff:203.0.113.9]:4444", []string{"rule-remote:10"}},
		"other port":                  {"192.0.2.5:40000 203.0.113.9:4445", []string{}},
		"inbound on a scored port":    {"192.0.2.5:80 203.0.113.9:4444", []string{}},
		"inbound on an unscored port": {"192.0.2.5:8081 203.0.113.9:4444", []string{"rule-remote:10"}},
	} {
		f := strings.Fields(c.sock)
		k := conn(500, "tcp", f[0], f[1])
		ds := only(Sweep(snap(append(web(), mk(10, 1, "/usr/bin/curl", map[int]uint64{5: 500})), http, k), withRules(pol(), c2Rule)), "rule-remote")
		if got := kinds(ds); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: %v", name, got)
		}
		if len(ds) == 1 && (ds[0].Remote == nil || ds[0].Remote.Addr != "203.0.113.9" || ds[0].Remote.Port != 4444) {
			t.Errorf("%s: %+v", name, ds[0].Remote)
		}
	}
	listening := lsn(500, "tcp", "0.0.0.0:4444")
	ds := Sweep(snap(append(web(), mk(10, 1, "/usr/bin/curl", map[int]uint64{5: 500})), listening), withRules(pol(), c2Rule))
	if len(only(ds, "rule-remote")) != 0 {
		t.Fatalf("listening socket matched: %+v", ds)
	}
}

func TestRules_EventConnect(t *testing.T) {
	s := snap(procs{systemd, mk(50, 1, "/usr/bin/curl", nil)})
	p := withRules(pol(), c2Rule)
	for _, kind := range []sensor.Kind{sensor.Connect, sensor.Send} {
		ds := Event(sensor.Event{Kind: kind, PID: 50, Dst: ap("203.0.113.9:4444"), Proto: "tcp"}, s, p)
		want(t, only(ds, "rule-remote"), "rule-remote:50")
	}
	ds := Event(sensor.Event{Kind: sensor.Connect, PID: 50, Dst: ap("203.0.113.9:4444"), Proto: "udp"}, s, p)
	want(t, only(ds, "rule-remote"))
}

func TestRules_NilIndex(t *testing.T) {
	hashes["/tmp/implant"] = "ff"
	defer delete(hashes, "/tmp/implant")
	s := snap(append(web(), mk(10, 1, "/tmp/implant", nil)))
	if ds := only(Sweep(s, pol()), "rule-hash"); len(ds) != 0 {
		t.Fatal(ds)
	}
	if ds := Event(sensor.Event{Kind: sensor.Exec, PID: 10, Filename: "/tmp/implant"}, s, pol()); len(only(ds, "rule-hash")) != 0 {
		t.Fatal(ds)
	}
}

func TestRules_NotSelf(t *testing.T) {
	hashes["/tmp/implant"] = "ff"
	defer delete(hashes, "/tmp/implant")
	p := withRules(pol(), rules.Rule{Kind: "hash", SHA256: "ff"})
	if ds := only(Sweep(snap(append(web(), mk(selfPID, 1, "/tmp/implant", nil))), p), "rule-hash"); len(ds) != 0 {
		t.Fatal(ds)
	}
}

// A container's own shells and interpreters are not in the host baseline,
// so their hashes could pass validation; a hash rule never matches them.
// The same names on the host, outside the baseline, still match.
func TestRules_HashSkipsContainerShells(t *testing.T) {
	hashes["/tmp/sh"] = "e1"
	defer delete(hashes, "/tmp/sh")
	p := withRules(pol(), rules.Rule{Kind: "hash", SHA256: "e1", From: "db01"})
	sh := mk(10, 1, "/tmp/sh", nil)
	sh.Cgroup = "0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope"
	if ds := only(Sweep(snap(append(web(), sh)), p), "rule-hash"); len(ds) != 0 {
		t.Fatalf("container shell: %+v", ds)
	}
	want(t, only(Sweep(snap(append(web(), mk(10, 1, "/tmp/sh", nil))), p), "rule-hash"), "rule-hash:10")
}

func TestRules_ParentHit(t *testing.T) {
	p := withRules(pol(), rules.Rule{Kind: "parent", ParentExe: "/usr/sbin/apache2", Exe: "/usr/bin/dash", From: "db01"})
	sshd := mk(800, 1, "/usr/sbin/sshd", nil)
	ps := append(web(), sshd, mk(950, 901, "/usr/bin/dash", nil), mk(951, 800, "/usr/bin/dash", nil))
	want(t, only(Sweep(snap(ps), p), "rule-parent"), "rule-parent:950")
	// A reused parent pid: the "parent" started after the child.
	late := mk(960, 970, "/usr/bin/dash", nil)
	newer := mk(970, 1, "/usr/sbin/apache2", nil)
	late.Start, newer.Start = 100, 200
	want(t, only(Sweep(snap(append(web(), late, newer)), p), "rule-parent"))
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 950, Filename: "/usr/bin/dash"}, snap(ps), p)
	want(t, only(ds, "rule-parent"), "rule-parent:950")
}

func TestRules_UnitHit(t *testing.T) {
	const fsum = "ab12000000000000000000000000000000000000000000000000000000000000"
	p := withRules(pol(), rules.Rule{Kind: "unit", Unit: "evil.service", SHA256: fsum, From: "db01"})
	x := mk(10, 1, "/opt/x", nil)
	x.Cgroup = "0::/system.slice/evil.service"
	p.UnitHash = func(u string) string {
		if u == "evil.service" {
			return fsum
		}
		return ""
	}
	want(t, only(Sweep(snap(append(web(), x)), p), "rule-unit"), "rule-unit:10")
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 10, Filename: "/opt/x"}, snap(append(web(), x)), p)
	want(t, only(ds, "rule-unit"), "rule-unit:10")
	p.UnitHash = func(string) string { return "cd" + fsum[2:] }
	want(t, only(Sweep(snap(append(web(), x)), p), "rule-unit"))
}

func TestRules_CronHit(t *testing.T) {
	p := withRules(pol(), rules.Rule{Kind: "cron", Command: "curl x | sh", From: "db01"})
	cron := mk(700, 1, "/usr/sbin/cron", nil)
	sh := mk(701, 700, "/usr/bin/dash", nil)
	sh.Cmdline = []string{"/bin/sh", "-c", "curl x | sh"}
	want(t, only(Sweep(snap(append(web(), cron, sh)), p), "rule-cron"), "rule-cron:701")
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 701, Filename: "/usr/bin/dash"}, snap(append(web(), cron, sh)), p)
	want(t, only(ds, "rule-cron"), "rule-cron:701")
	other := mk(702, 1, "/usr/bin/dash", nil)
	other.Cmdline = sh.Cmdline
	want(t, only(Sweep(snap(append(web(), other)), p), "rule-cron"))
}

// A unit rule never matches inside a scored service's unit: its helpers
// would die with it.
func TestRules_UnitSparesScoredService(t *testing.T) {
	const fsum = "ab12000000000000000000000000000000000000000000000000000000000000"
	p := withRules(pol(), rules.Rule{Kind: "unit", Unit: "apache2.service", SHA256: fsum, From: "db01"})
	p.UnitHash = func(string) string { return fsum }
	srv := mk(20, 1, "/usr/sbin/apache2", nil)
	helper := mk(21, 20, "/usr/lib/apache2/helper", nil)
	srv.Cgroup, helper.Cgroup = "0::/system.slice/apache2.service", "0::/system.slice/apache2.service"
	want(t, only(Sweep(snap(procs{srv, helper}), p), "rule-unit"))
	ds := Event(sensor.Event{Kind: sensor.Exec, PID: 21, Filename: helper.Exe}, snap(procs{srv, helper}), p)
	want(t, only(ds, "rule-unit"))
}
