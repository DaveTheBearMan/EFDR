package agent

import (
	"testing"

	"xdr/internal/fleet"
)

func procOrderFor(pid, sum string) fleet.Order {
	return fleet.Order{Kind: "proc", Name: pid, Value: []byte(`{"verdict":"kill","sha256":"` + sum + `"}`)}
}

func TestProcOrder_KillsHeldProcessOnHash(t *testing.T) {
	r := newRig(t)
	svc := mk(700, 1, 33, "/usr/sbin/apache2") // guarded: the rig's guard_exes
	r.snap = tree(svc)
	r.a.snap = r.snap
	r.a.onOrder(procOrderFor("700", "sum:/usr/sbin/apache2"))
	if len(r.kills) != 1 || r.kills[0].pid != 700 {
		t.Fatalf("kills %+v (refused %+v)", r.kills, r.kind("proc-refused"))
	}
	if r.kills[0].protect(svc) {
		t.Fatal("the operator said yes to the scored process, yet the kill spares it")
	}
	if !r.kills[0].protect(mk(selfPID, 1, 0, "/x")) {
		t.Fatal("the agent does not spare itself")
	}
	if got := r.kind("proc-killed"); len(got) != 1 || got[0].PID != 700 {
		t.Fatalf("proc-killed: %+v", got)
	}
}

func TestProcOrder_Refusals(t *testing.T) {
	r := newRig(t)
	grayProc := mk(710, 1, 2001, "/usr/sbin/apache2")
	r.snap = tree(mk(700, 1, 33, "/usr/sbin/apache2"), grayProc, mk(selfPID, 1, 0, "/usr/local/sbin/xdr"))
	r.a.snap = r.snap
	for name, o := range map[string]fleet.Order{
		"a wrong hash":            procOrderFor("700", "sum:/tmp/other"),
		"a pid that is not there": procOrderFor("999", "sum:/usr/sbin/apache2"),
		"a gray user's process":   procOrderFor("710", "sum:/usr/sbin/apache2"),
		"the agent itself":        procOrderFor("77", "sum:/usr/local/sbin/xdr"),
		"no hash":                 procOrderFor("700", ""),
		"a bad pid":               procOrderFor("7x", "sum:/usr/sbin/apache2"),
	} {
		before := len(r.kind("proc-refused"))
		r.a.onOrder(o)
		if len(r.kind("proc-refused")) != before+1 {
			t.Errorf("%s: not refused", name)
		}
	}
	if len(r.kills) != 0 {
		t.Fatalf("something was killed: %+v", r.kills)
	}
}
