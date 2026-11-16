package agent

import (
	"fmt"
	"strconv"

	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/proc"
)

// procOrder acts on a `proc` order: the operator's yes to killing a
// process the agent held because it is a scored service. The process must
// still run the binary the order names by hash (a pid reused by something
// else is refused), must not be a gray account's, and is killed with its
// tree; nothing is spared but the agent itself. The caller holds a.mu.
func (a *agent) procOrder(name, sum string) {
	refuse := func(why string) {
		a.record(incident.Incident{Kind: "proc-refused", Action: "alert", Severity: model.SevHigh, Detail: fmt.Sprintf("kill order for %s: %s", name, why)})
	}
	pid, err := strconv.Atoi(name)
	if err != nil || pid <= 1 {
		refuse("not a pid")
		return
	}
	if sum == "" {
		refuse("no hash to check the process against")
		return
	}
	var p *proc.Proc
	if a.snap != nil {
		p = a.snap.Procs[pid]
	}
	switch {
	case p == nil:
		refuse("not running")
		return
	case pid == a.pol.Self:
		refuse("the agent")
		return
	case a.pol.IsGray(a.snap, p):
		refuse("a gray account's process")
		return
	case a.pol.Hash == nil || a.pol.Hash(p) != sum:
		refuse("its binary is not the one the order names")
		return
	}
	protect := func(q *proc.Proc) bool { return q.PID == a.pol.Self }
	killed, err := a.kill(pid, p.Start, protect)
	in := incident.Incident{Kind: "proc-killed", Action: "killed", Severity: model.SevHigh, PID: pid, UID: p.UID, Exe: p.Exe, SHA256: sum,
		Detail: fmt.Sprintf("killed on the operator's order (%d processes)", len(killed))}
	if err != nil {
		in.Action, in.Detail = "kill-failed", "kill order: "+err.Error()
	}
	a.record(in)
}
