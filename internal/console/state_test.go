package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/controller"
	"xdr/internal/fleet"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/rules"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newState(t *testing.T) (*State, *clock, string) {
	t.Helper()
	dir := t.TempDir()
	c := &clock{t0}
	s, err := NewState(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, dir
}

func inc(host, kind, action string, at time.Duration, edit func(*incident.Incident)) incident.Incident {
	in := incident.Incident{Host: host, Kind: kind, Action: action, Severity: model.SevHigh, Time: t0.Add(at)}
	if edit != nil {
		edit(&in)
	}
	return in
}

func approval(v View, id string) *Approval {
	for i := range v.Approvals {
		if v.Approvals[i].ID == id {
			return &v.Approvals[i]
		}
	}
	return nil
}

func TestState_ApprovalsFromIncidents(t *testing.T) {
	s, c, _ := newState(t)
	c.t = t0.Add(10 * time.Second)
	s.Feed(inc("web01", "session-pending", "alert", 0, func(i *incident.Incident) {
		i.User, i.Detail = "alice", "session 7 from 192.0.2.7 (ends in 1m30s)"
	}))
	v := s.View(nil, nil)
	a := approval(v, "s:web01:7")
	if a == nil || a.Kind != "session" || !a.Deadline.Equal(t0.Add(90*time.Second)) || strings.Join(a.Actions, ",") != "approve,kill" {
		t.Fatalf("pending session: %+v in %+v", a, v.Approvals)
	}
	if len(v.Sessions) != 1 || v.Sessions[0].Status != "pending" || v.Sessions[0].User != "alice" || v.Sessions[0].From != "192.0.2.7" {
		t.Fatalf("session rows: %+v", v.Sessions)
	}
	s.Feed(inc("web01", "session-terminated", "killed", 95*time.Second, func(i *incident.Incident) {
		i.User, i.Detail = "alice", "session 7 from 192.0.2.7: not approved within 1m30s"
	}))
	v = s.View(nil, nil)
	if approval(v, "s:web01:7") != nil || v.Sessions[0].Status != "ended" {
		t.Fatalf("after the session ended: %+v %+v", v.Approvals, v.Sessions)
	}

	s.Feed(inc("db01", "user-disabled", "repaired", 20*time.Second, func(i *incident.Incident) { i.User = "evil" }))
	s.Feed(inc("web01", "service-shell", "held", 30*time.Second, func(i *incident.Incident) {
		i.PID, i.Exe, i.SHA256, i.Detail = 950, "/usr/bin/dash", "abcdef0123456789abcdef", "started under apache2 (pid 900)"
	}))
	s.Feed(inc("web01", "file-drift", "alert", 40*time.Second, func(i *incident.Incident) {
		i.Path, i.SHA256, i.Detail = "/etc/cron.d/evil", "0123456789abcdef", "cron added: new file (sha256 0123456789ab)"
	}))
	s.Feed(inc("web01", "file-drift", "alert", 41*time.Second, func(i *incident.Incident) {
		i.Path, i.Detail = "/etc/hosts", "file altered: size"
	}))
	v = s.View(nil, nil)
	fid := fleet.FileID("/etc/cron.d/evil")
	for id, kind := range map[string]string{"u:db01:evil": "user", "p:web01:950:abcdef012345": "proc", "f:web01:" + fid: "file"} {
		if a := approval(v, id); a == nil || a.Kind != kind {
			t.Errorf("%s: %+v", id, a)
		}
	}
	if a := approval(v, "p:web01:950:abcdef012345"); a == nil || a.Params["pid"] != "950" || a.Params["sha256"] != "abcdef0123456789abcdef" || strings.Join(a.Actions, ",") != "kill,ignore" {
		t.Errorf("held process: %+v", a)
	}
	if a := approval(v, "f:web01:"+fleet.FileID("/etc/hosts")); a != nil {
		t.Errorf("an altered base-image file is not offered for removal: %+v", a)
	}
	// removal, then undo for 24 h, then restored
	s.Feed(inc("web01", "file-removed", "repaired", 60*time.Second, func(i *incident.Incident) { i.Path = "/etc/cron.d/evil" }))
	v = s.View(nil, nil)
	if approval(v, "f:web01:"+fid) != nil {
		t.Fatal("the removal approval stayed")
	}
	u := approval(v, "fu:web01:"+fid)
	if u == nil || strings.Join(u.Actions, ",") != "undo" || !u.Deadline.Equal(t0.Add(60*time.Second+24*time.Hour)) {
		t.Fatalf("undo entry: %+v", u)
	}
	s.Feed(inc("web01", "file-restored", "repaired", 70*time.Second, func(i *incident.Incident) { i.Path = "/etc/cron.d/evil" }))
	if approval(s.View(nil, nil), "fu:web01:"+fid) != nil {
		t.Fatal("the undo entry stayed after the restore")
	}
}

func TestState_AlertSteps(t *testing.T) {
	s, _, _ := newState(t)
	s.Feed(inc("web01", "egress", "killed", 0, func(i *incident.Incident) {
		i.SHA256, i.Remote, i.Detail = "aa11", &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"}, "tcp to 203.0.113.9:4444"
		i.Chain = []incident.ProcRef{{PID: 9142, Comm: "beacon"}, {PID: 1, Comm: "systemd"}}
	}))
	s.Feed(inc("web01", "rule-promoted", "alert", 5*time.Second, func(i *incident.Incident) {
		i.SHA256, i.Detail = "aa11", "rule b287a9f6b29b2f2a hash aa11 promoted, version 3"
	}))
	s.Feed(inc("db01", "fw-block", "repaired", 8*time.Second, func(i *incident.Incident) {
		i.Detail = "blocked 203.0.113.9:4444/tcp: rule b287a9f6b29b2f2a from web01"
	}))
	s.Feed(inc("web01", "rule-promoted", "alert", 5*time.Minute, func(i *incident.Incident) {
		i.SHA256, i.Detail = "aa11", "rule zzzz hash aa11 promoted, version 9"
	}))
	v := s.View(nil, nil)
	var a *Alert
	for i := range v.Alerts {
		if v.Alerts[i].Kind == "egress" {
			a = &v.Alerts[i]
		}
	}
	if a == nil {
		t.Fatalf("no egress alert in %+v", v.Alerts)
	}
	steps := strings.Join(a.Steps, "|")
	for _, want := range []string{"killed", "rule b287a9f6b29b2f2a written", "blocked on db01"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q: %s", want, steps)
		}
	}
	if strings.Contains(steps, "zzzz") {
		t.Errorf("a rule written minutes later is not a step: %s", steps)
	}
	if a.Remote != "203.0.113.9:4444/tcp" || len(a.Chain) != 2 || !strings.Contains(a.Chain[0], "beacon") {
		t.Errorf("fields: %+v", a)
	}
}

func TestState_Summary(t *testing.T) {
	s, _, _ := newState(t)
	s.Feed(inc("web01", "egress", "killed", 0, nil))
	s.Feed(inc("web01", "revshell-stdio", "killed", time.Second, nil))
	s.Feed(inc("web01", "egress", "alert", 2*time.Second, nil))
	s.Feed(inc("db01", "fw-block", "repaired", 3*time.Second, func(i *incident.Incident) { i.Detail = "blocked 203.0.113.9:4444/tcp: rule x from web01" }))
	hosts := []controller.HostStatus{{Name: "web01", Seen: true}, {Name: "db01", Seen: true}, {Name: "mail01", Seen: true, Silent: true}, {Name: "new01"}}
	set := &rules.Set{Rules: make([]rules.Rule, 3)}
	v := s.View(hosts, set)
	want := Summary{Killed: 2, AgentsUp: 2, AgentsTotal: 4, Blocks: 1}
	if v.Summary != want || v.Rules != 3 {
		t.Fatalf("summary %+v rules %d, want %+v", v.Summary, v.Rules, want)
	}
	if len(v.Hosts) != 4 || v.Hosts[2].Status != "silent" || v.Hosts[3].Status != "never" || v.Hosts[0].Alerts == 0 && v.Hosts[1].Alerts == 0 {
		t.Fatalf("hosts: %+v", v.Hosts)
	}
	s.Feed(inc("db01", "fw-unblock", "repaired", 4*time.Second, func(i *incident.Incident) { i.Detail = "unblocked 203.0.113.9:4444/tcp" }))
	if v = s.View(hosts, set); v.Summary.Blocks != 0 {
		t.Fatalf("blocks after the unblock: %d", v.Summary.Blocks)
	}
}

func TestState_HandledSurvivesRestart(t *testing.T) {
	s, _, dir := newState(t)
	pending := inc("web01", "session-pending", "alert", 0, func(i *incident.Incident) { i.Detail = "session 7 from 192.0.2.7 (ends in 1m30s)" })
	s.Feed(pending)
	if _, err := s.Handle("s:web01:7", "approve"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Handle("s:web01:7", "approve"); err != ErrHandled {
		t.Fatalf("second time: %v", err)
	}
	if _, err := s.Handle("s:web01:404", "approve"); err != ErrUnknown {
		t.Fatalf("unknown: %v", err)
	}
	if approval(s.View(nil, nil), "s:web01:7") != nil {
		t.Fatal("still an approval after it was handled")
	}
	s2, err := NewState(dir, (&clock{t0}).now)
	if err != nil {
		t.Fatal(err)
	}
	s2.Feed(pending) // the controller replays its log
	if approval(s2.View(nil, nil), "s:web01:7") != nil {
		t.Fatal("a handled approval came back after a restart")
	}
	if st, err := os.Stat(filepath.Join(dir, "console-state.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", st, err)
	}
	if s2.View(nil, nil).Sessions[0].Status != "approved" {
		t.Fatalf("the session row does not say it was approved: %+v", s2.View(nil, nil).Sessions)
	}
}

func TestState_Bounded(t *testing.T) {
	s, _, dir := newState(t)
	for i := 0; i < 10000; i++ {
		s.Feed(inc("web01", "egress", "alert", time.Duration(i)*time.Millisecond, nil))
	}
	big := strings.Repeat("x", 1<<20)
	s.Feed(inc("web01", "egress", "alert", time.Hour, func(i *incident.Incident) { i.Detail, i.Path = big, big }))
	if n := s.Len(); n > 2000 {
		t.Fatalf("%d incidents kept", n)
	}
	for _, a := range s.View(nil, nil).Alerts {
		if len(a.Detail) > 4096 || len(a.Path) > 4096 {
			t.Fatalf("a %d byte detail was kept", len(a.Detail))
		}
	}
	for i := 0; i < 700; i++ {
		s.Feed(inc("web01", "user-new", "alert", time.Duration(i)*time.Second, func(in *incident.Incident) { in.User = "u" + string(rune('a'+i%26)) + strings.Repeat("z", i%50) }))
	}
	for i := 0; i < 700; i++ {
		s.Handle("u:web01:u"+string(rune('a'+i%26))+strings.Repeat("z", i%50), "ignore")
	}
	if n := s.HandledLen(); n > 500 {
		t.Fatalf("%d handled ids kept", n)
	}
	if st, err := os.Stat(filepath.Join(dir, "console-state.json")); err == nil && st.Size() > 200<<10 {
		t.Fatalf("state file %d bytes", st.Size())
	}
}
