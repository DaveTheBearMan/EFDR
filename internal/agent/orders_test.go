package agent

import (
	"strconv"
	"testing"
	"time"

	"xdr/internal/fleet"
	"xdr/internal/testfs"
)

func order(kind, name, verdict string) fleet.Order {
	return fleet.Order{Kind: kind, Name: name, Value: []byte(`{"verdict":"` + verdict + `"}`)}
}

func TestAgentOrders_ApproveKeepsSession(t *testing.T) {
	r, _ := tokenRig(t)
	sessionFile(t, r.root, "7", "alice", "192.0.2.7", 4242)
	r.a.sessions(r.snap)
	r.a.onOrder(order("session", "7", "approve"))
	r.now = r.now.Add(10 * time.Minute)
	r.a.sessions(r.snap)
	if len(r.kind("session-terminated")) != 0 {
		t.Fatal("approved session ended")
	}
}

func TestAgentOrders_KillEndsApproved(t *testing.T) {
	r, ran := gateOn(t)
	r.a.state = t.TempDir()
	sessionFile(t, r.root, "7", "alice", "192.0.2.7", 4242)
	r.a.onOrder(order("session", "7", "approve"))
	r.a.sessions(r.snap)
	r.a.onOrder(order("session", "7", "kill"))
	r.a.sessions(r.snap)
	if terminates(*ran) != 1 || len(r.kind("session-terminated")) != 1 {
		t.Fatalf("kill order: %v", *ran)
	}
}

func TestAgentOrders_SurviveRestart(t *testing.T) {
	r, _ := tokenRig(t)
	r.a.onOrder(order("session", "7", "approve"))
	r.a.onOrder(order("user", "evil", "approve"))
	r.a.onOrder(order("session", "8", "kill"))
	r.a.onOrder(fleet.Order{Kind: "session", Name: "8", Deleted: true})
	r.a.approved, r.a.ended, r.a.okUsers = nil, nil, nil
	r.a.loadOrders()
	if !r.a.approved["7"] || !r.a.okUsers["evil"] || r.a.ended["8"] {
		t.Fatalf("approved %v ended %v users %v", r.a.approved, r.a.ended, r.a.okUsers)
	}
}

func bootFiles(t *testing.T, r *rig, id string, btime int64) {
	testfs.File(t, r.root, "proc/sys/kernel/random/boot_id", id+"\n", 0o644)
	testfs.File(t, r.root, "proc/stat", "cpu  1 2 3\nbtime "+strconv.FormatInt(btime, 10)+"\nprocesses 5\n", 0o644)
}

// Session ids restart at 1 on every boot: what was approved or ordered
// ended before a reboot must not follow the new session with that id.
func TestAgentOrders_SessionOrdersDoNotSurviveReboot(t *testing.T) {
	r, _ := tokenRig(t)
	bootFiles(t, r, "boot-one", 1000)
	r.a.loadOrders()
	r.a.onOrder(order("session", "5", "approve"))
	r.a.onOrder(order("session", "6", "kill"))
	r.a.onOrder(order("user", "evil", "approve"))
	bootFiles(t, r, "boot-two", 5000)
	r.a.approved, r.a.ended, r.a.okUsers = nil, nil, nil
	r.a.loadOrders()
	if r.a.approved["5"] || r.a.ended["6"] {
		t.Fatalf("session orders survived a reboot: %v %v", r.a.approved, r.a.ended)
	}
	if !r.a.okUsers["evil"] {
		t.Fatal("a user approval is not tied to a boot")
	}
	// The same boot keeps them.
	r.a.onOrder(fleet.Order{Kind: "session", Name: "5", Value: []byte(`{"verdict":"approve","at":5100}`)})
	r.a.approved = nil
	r.a.loadOrders()
	if !r.a.approved["5"] {
		t.Fatal("lost within a boot")
	}
}

// etcd replays the orders it holds on every connect: one put before this
// boot is stale, whatever session now has that id.
func TestAgentOrders_ReplayedStaleSessionOrderIgnored(t *testing.T) {
	r, _ := tokenRig(t)
	bootFiles(t, r, "b", 5000)
	r.a.loadOrders()
	stale := fleet.Order{Kind: "session", Name: "5", Value: []byte(`{"verdict":"approve","at":3000}`)}
	r.a.onOrder(stale)
	if r.a.approved["5"] {
		t.Fatal("a pre-boot approval applied")
	}
	fresh := fleet.Order{Kind: "session", Name: "5", Value: []byte(`{"verdict":"approve","at":5100}`)}
	r.a.onOrder(fresh)
	if !r.a.approved["5"] {
		t.Fatal("a post-boot approval ignored")
	}
	none := fleet.Order{Kind: "session", Name: "6", Value: []byte(`{"verdict":"kill"}`)}
	r.a.onOrder(none)
	if r.a.ended["6"] {
		t.Fatal("an order with no time applied")
	}
}
