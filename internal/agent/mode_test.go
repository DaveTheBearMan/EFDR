package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/detect"
	"xdr/internal/fleet"
	"xdr/internal/model"
)

func modeOrder(kill bool, at time.Time) fleet.Order {
	b, _ := json.Marshal(map[string]any{"kill": kill, "at": at, "by": "console"})
	return fleet.Order{Kind: "mode", Value: b}
}

// beacon runs one egress detection and says what was done about it.
func beaconAction(t *testing.T, r *rig) string {
	t.Helper()
	n := len(r.got)
	x := mk(300, 100, 1000, fmt.Sprintf("/tmp/x%d", n)) // not folded into the last one by the log
	r.a.handle(tree(x), []detect.Detection{egress(x)})
	for _, in := range r.got[n:] {
		if in.Kind == "egress" {
			return in.Action
		}
	}
	t.Fatalf("no egress incident: %+v", r.got[n:])
	return ""
}

func TestMode_OrderTurnsKillOnAndOff(t *testing.T) {
	r := newRig(t)
	r.a.cfg.Kill = false
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("config off: %s", got)
	}
	r.a.onOrder(modeOrder(true, r.now))
	if got := beaconAction(t, r); got != "killed" {
		t.Fatalf("ordered on: %s", got)
	}
	ms := r.kind("mode")
	if len(ms) != 1 || ms[0].Action != "kill-on" || ms[0].Severity != model.SevMedium || !strings.Contains(ms[0].Detail, "console") {
		t.Fatalf("mode incidents: %+v", ms)
	}
	r.a.onOrder(modeOrder(false, r.now.Add(time.Second)))
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("ordered off: %s", got)
	}
	if ms := r.kind("mode"); len(ms) != 2 || ms[1].Action != "kill-off" {
		t.Fatalf("mode incidents: %+v", ms)
	}
	// etcd replays the order on every connect: no second incident.
	r.a.onOrder(modeOrder(false, r.now.Add(time.Second)))
	if ms := r.kind("mode"); len(ms) != 2 {
		t.Fatalf("a replay was recorded: %+v", ms)
	}
}

func TestMode_OlderOrderIgnored(t *testing.T) {
	r := newRig(t)
	r.a.onOrder(modeOrder(false, r.now))
	r.a.onOrder(modeOrder(true, r.now.Add(-time.Minute)))
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("an older order took: %s", got)
	}
	if ms := r.kind("mode"); len(ms) != 1 {
		t.Fatalf("mode incidents: %+v", ms)
	}
}

func TestMode_PersistedAndLoadedAtStart(t *testing.T) {
	r := newRig(t)
	r.a.onOrder(modeOrder(false, r.now))
	path := filepath.Join(r.a.state, "mode.json")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode file: %v %v", st, err)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("the temporary file was left")
	}
	// A restart: a new agent over the same state, config says kill.
	r.a.mode = nil
	r.a.loadMode()
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("after a restart: %s", got)
	}
	// The order replayed on connect is the one already applied.
	r.a.onOrder(modeOrder(false, r.now))
	if ms := r.kind("mode"); len(ms) != 1 {
		t.Fatalf("mode incidents: %+v", ms)
	}
	// Still older ones are refused after the restart too.
	r.a.onOrder(modeOrder(true, r.now.Add(-time.Hour)))
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("older after restart: %s", got)
	}
}

func TestMode_NoFileIsConfig(t *testing.T) {
	r := newRig(t)
	r.a.loadMode()
	if got := beaconAction(t, r); got != "killed" {
		t.Fatalf("config on, no mode file: %s", got)
	}
	os.MkdirAll(r.a.state, 0o700)
	os.WriteFile(filepath.Join(r.a.state, "mode.json"), []byte("{not json"), 0o600)
	r.a.loadMode()
	if got := beaconAction(t, r); got != "killed" {
		t.Fatalf("damaged mode file: %s", got)
	}
}

func TestMode_ReloadKeepsTheChoice(t *testing.T) {
	r := newRig(t)
	r.a.onOrder(modeOrder(false, r.now))
	cfg := *r.a.cfg
	cfg.Kill = true
	if err := r.a.reload(&cfg); err != nil {
		t.Fatal(err)
	}
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("a reload undid the operator's choice: %s", got)
	}
}

func TestMode_BadOrdersIgnoredAndReportedOnce(t *testing.T) {
	r := newRig(t)
	r.a.cfg.Kill = false
	bad := []fleet.Order{
		{Kind: "mode", Value: []byte(`{not json`)},
		{Kind: "mode", Value: []byte(`{"at":"2026-11-10T12:00:00Z"}`)}, // no kill
		{Kind: "mode", Value: []byte(`{"kill":"yes","at":"2026-11-10T12:00:00Z"}`)},
		{Kind: "mode", Value: []byte(`{"kill":true}`)}, // no time
		modeOrder(true, r.now.Add(6*time.Minute)),      // from the future
	}
	for _, o := range bad {
		r.a.onOrder(o)
		r.a.onOrder(o) // replayed
	}
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("a bad order took: %s", got)
	}
	if ms := r.kind("mode"); len(ms) != 0 {
		t.Fatalf("mode incidents: %+v", ms)
	}
	if rs := r.kind("mode-refused"); len(rs) != len(bad) {
		t.Fatalf("%d refusals for %d bad orders: %+v", len(rs), len(bad), rs)
	}
	// Within the clock slack is fine.
	r.a.onOrder(modeOrder(true, r.now.Add(4*time.Minute)))
	if got := beaconAction(t, r); got != "killed" {
		t.Fatalf("an order 4 min ahead: %s", got)
	}
	// A deleted key changes nothing.
	r.a.onOrder(fleet.Order{Kind: "mode", Deleted: true})
	if got := beaconAction(t, r); got != "killed" {
		t.Fatalf("after a delete: %s", got)
	}
}

// Turning kill on never overrides a pause or a protection.
func TestMode_OnKeepsProtections(t *testing.T) {
	r := newRig(t)
	r.a.cfg.Kill = false
	r.a.onOrder(modeOrder(true, r.now))
	s := tree()
	r.a.handle(s, []detect.Detection{egress(s.Procs[900])})
	if len(r.kills) != 0 || r.kind("egress")[0].Action != "held" {
		t.Fatalf("a guarded process: %+v %+v", r.kills, r.kind("egress"))
	}
	r.a.pausedUntil = r.now.Add(time.Hour)
	if got := beaconAction(t, r); got != "would-kill" {
		t.Fatalf("paused: %s", got)
	}
}
