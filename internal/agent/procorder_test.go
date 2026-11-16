package agent

import (
	"strconv"
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

func timedProcOrder(pid, sum string, at int64) fleet.Order {
	return fleet.Order{Kind: "proc", Name: pid, Value: []byte(`{"verdict":"kill","sha256":"` + sum + `","at":` + strconv.FormatInt(at, 10) + `}`)}
}

// etcd replays every standing order on each connect, and nothing deletes
// them: a kill the operator ordered once must not be carried out again by a
// reconnect, nor after a reboot, when pids repeat and the service is back.
func TestProcOrder_AppliedOnceAndNotAfterReboot(t *testing.T) {
	r, _ := tokenRig(t)
	bootFiles(t, r, "boot-one", 1000)
	r.a.loadOrders()
	svc := mk(700, 1, 33, "/usr/sbin/apache2")
	r.snap = tree(svc)
	r.a.snap = r.snap
	o := timedProcOrder("700", "sum:/usr/sbin/apache2", 1500)
	r.a.onOrder(o)
	r.a.onOrder(o) // a reconnect replays it
	if len(r.kills) != 1 {
		t.Fatalf("%d kills for one order replayed", len(r.kills))
	}
	// An agent restart on the same boot keeps what it applied.
	r.a.ordersDone = nil
	r.a.loadOrders()
	r.a.onOrder(o)
	if len(r.kills) != 1 {
		t.Fatalf("a restart of the agent repeated the kill: %d", len(r.kills))
	}
	// A reboot: the order is from before it, the service has the same pid
	// and hash again.
	bootFiles(t, r, "boot-two", 5000)
	r.a.loadOrders()
	r.a.onOrder(o)
	if len(r.kills) != 1 {
		t.Fatalf("an order from before the reboot killed the restarted service: %d", len(r.kills))
	}
	// A fresh order after the reboot is obeyed.
	r.a.onOrder(timedProcOrder("700", "sum:/usr/sbin/apache2", 5100))
	if len(r.kills) != 2 {
		t.Fatalf("a new order was not obeyed: %d", len(r.kills))
	}
	// So is one with no time, but only where the boot is unknown.
	r2 := newRig(t)
	r2.snap = tree(svc)
	r2.a.snap = r2.snap
	r2.a.onOrder(procOrderFor("700", "sum:/usr/sbin/apache2"))
	if len(r2.kills) != 1 {
		t.Fatal("an order with no time was refused where the boot time is unknown")
	}
}

func TestFileOrder_AppliedOnce(t *testing.T) {
	r := scanRig(t)
	id := reported(t, r, "/etc/cron.d/evil", "* * * * * root /tmp/x\n", 0o640)
	o := fleet.Order{Kind: "file", Name: id, Value: []byte(`{"verdict":"remove","at":1500}`)}
	r.a.onOrder(o)
	r.a.onOrder(o)
	if n := len(r.kind("file-removed")) + len(r.kind("file-refused")); n != 1 {
		t.Fatalf("a replayed order acted %d times: %+v %+v", n, r.kind("file-removed"), r.kind("file-refused"))
	}
}
