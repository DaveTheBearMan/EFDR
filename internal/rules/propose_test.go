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
