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
