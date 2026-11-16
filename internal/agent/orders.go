package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xdr/internal/collect"
	"xdr/internal/fleet"
)

// orders is what the controller's orders left standing, kept in
// State/orders.json so they hold across a restart with etcd down.
type orders struct {
	Approved map[string]bool `json:"approved"` // session ids
	Ended    map[string]bool `json:"ended"`    // session ids
	Users    map[string]bool `json:"users"`    // new accounts approved
	Disabled map[string]bool `json:"disabled"` // accounts the agent locked
	BootID   string          `json:"boot_id"`  // session ids mean nothing across boots
	Done     map[string]bool `json:"done"`     // file and proc orders acted on, this boot
}

// onOrder takes in one order from To(host).
func (a *agent) onOrder(o fleet.Order) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if o.Kind == "creds" {
		if !o.Deleted {
			a.onCreds(o.Value)
		}
		return
	}
	var v struct {
		Verdict string `json:"verdict"`
		At      int64  `json:"at"`     // when the controller put it (unix seconds)
		SHA256  string `json:"sha256"` // proc: the exe hash the process must have
	}
	if !o.Deleted && json.Unmarshal(o.Value, &v) != nil {
		a.logf("order %s/%s: bad value", o.Kind, o.Name)
		return
	}
	a.initOrders()
	switch o.Kind {
	case "file", "proc":
		// etcd replays what it holds on every connect and nothing deletes an
		// order: one is acted on once, and never when it was put before this
		// boot (the same pid and hash can be a restarted service).
		if o.Deleted || !a.firstTime(o.Kind, o.Name, v.Verdict, v.SHA256, v.At) {
			return
		}
		if o.Kind == "file" {
			a.fileOrder(o.Name, v.Verdict)
		} else if v.Verdict == "kill" {
			a.procOrder(o.Name, v.SHA256)
		}
		return
	case "session":
		// Session ids restart at every boot, and etcd replays what it
		// holds: an order older than this boot is for another session.
		if !o.Deleted && a.btime > 0 && v.At+bootSlack < a.btime {
			a.logf("order session/%s: put before this boot; ignored", o.Name)
			return
		}
		delete(a.approved, o.Name)
		delete(a.ended, o.Name)
		switch {
		case o.Deleted:
		case v.Verdict == "approve":
			a.approved[o.Name] = true
		case v.Verdict == "kill":
			a.ended[o.Name] = true
		}
	case "user":
		if o.Deleted || v.Verdict != "approve" {
			delete(a.okUsers, o.Name)
		} else {
			a.okUsers[o.Name] = true
		}
	default:
		return
	}
	a.saveOrders()
}

func (a *agent) initOrders() {
	if a.approved == nil {
		a.approved = map[string]bool{}
	}
	if a.ended == nil {
		a.ended = map[string]bool{}
	}
	if a.okUsers == nil {
		a.okUsers = map[string]bool{}
	}
	if a.disabled == nil {
		a.disabled = map[string]bool{}
	}
}

func (a *agent) ordersPath() string { return filepath.Join(a.state, "orders.json") }

func (a *agent) saveOrders() {
	b, _ := json.Marshal(orders{a.approved, a.ended, a.okUsers, a.disabled, a.bootID, a.ordersDone})
	if err := os.MkdirAll(a.state, 0o700); err == nil {
		tmp := a.ordersPath() + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, a.ordersPath()) == nil {
			return
		}
	}
	a.logf("orders: cannot save %s", a.ordersPath())
}

// loadOrders reads the orders kept before a restart.
func (a *agent) loadOrders() {
	var o orders
	if b, err := collect.ReadFile(a.ordersPath(), 4<<20); err == nil {
		json.Unmarshal(b, &o)
	}
	a.approved, a.ended, a.okUsers, a.disabled, a.ordersDone = o.Approved, o.Ended, o.Users, o.Disabled, o.Done
	a.bootID, a.btime = bootInfo(a.root)
	if o.BootID != a.bootID {
		// Kept across a restart of the agent, not of the box.
		a.approved, a.ended, a.ordersDone = nil, nil, nil
	}
	a.initOrders()
}

// bootSlack is how far the jump box's clock may differ from the box's.
const bootSlack = 60

// bootInfo is this boot's id and start time (unix seconds): "" and 0 when
// unreadable, in which case nothing is held to a boot.
func bootInfo(root string) (id string, btime int64) {
	if b, err := collect.ReadFile(filepath.Join(root, "proc/sys/kernel/random/boot_id"), 256); err == nil {
		id = strings.TrimSpace(string(b))
	}
	if b, err := collect.ReadFile(filepath.Join(root, "proc/stat"), 1<<20); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "btime "); ok {
				btime, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			}
		}
	}
	return id, btime
}

// maxDone bounds the orders remembered as acted on.
const maxDone = 1000

// firstTime reports whether the file or proc order (kind, name, verdict, sha) put at `at`
// should be acted on: it was put after this boot began (within the clock
// slack) and has not been acted on yet. It records the order as acted on.
// The caller holds a.mu.
func (a *agent) firstTime(kind, name, verdict, sha string, at int64) bool {
	if a.btime > 0 && at+bootSlack < a.btime {
		a.logf("order %s/%s: put before this boot; ignored", kind, name)
		return false
	}
	key := fmt.Sprintf("%s/%s/%s/%s/%d", kind, name, verdict, sha, at)
	if a.ordersDone[key] {
		return false
	}
	if a.ordersDone == nil || len(a.ordersDone) >= maxDone {
		a.ordersDone = map[string]bool{}
	}
	a.ordersDone[key] = true
	a.saveOrders()
	return true
}
