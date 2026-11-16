package agent

import (
	"encoding/json"
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
		At      int64  `json:"at"` // when the controller put it (unix seconds)
	}
	if !o.Deleted && json.Unmarshal(o.Value, &v) != nil {
		a.logf("order %s/%s: bad value", o.Kind, o.Name)
		return
	}
	a.initOrders()
	switch o.Kind {
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
	b, _ := json.Marshal(orders{a.approved, a.ended, a.okUsers, a.disabled, a.bootID})
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
	a.approved, a.ended, a.okUsers, a.disabled = o.Approved, o.Ended, o.Users, o.Disabled
	a.bootID, a.btime = bootInfo(a.root)
	if o.BootID != a.bootID {
		// Kept across a restart of the agent, not of the box.
		a.approved, a.ended = nil, nil
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
