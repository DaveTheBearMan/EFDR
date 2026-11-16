package agent

import (
	"testing"
	"time"

	"xdr/internal/fleet"
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
