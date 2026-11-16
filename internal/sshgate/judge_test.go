package sshgate

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestJudge_Table(t *testing.T) {
	c := gateConfig(t, `{"jump":["192.0.2.7"],"gray_users":["gray1"],"ssh":{"blue_users":["alice"],"recovery":"xdrrecover","recovery_key":"k","auto":["xdrops"],"grace":"90s"}}`)
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	jump, other := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("203.0.113.5")
	base := map[string]uint32{"root": 0, "alice": 1001, "gray1": 2001}
	sess := func(id, user string, from netip.Addr) Session {
		return Session{ID: id, User: user, Service: "sshd", Class: "user", RemoteAddr: from, RemoteHost: from.String()}
	}
	for _, row := range []struct {
		name  string
		s     Session
		first time.Duration // before now
		p     Policy
		want  Verdict
		why   string
	}{
		{"gray", sess("1", "gray1", other), time.Hour, Policy{}, Alert, "gray login from 203.0.113.5"},
		{"gray killed", sess("1", "gray1", other), 0, Policy{Killed: map[string]bool{"1": true}}, Alert, "gray"},
		{"recovery", sess("2", "xdrrecover", jump), time.Hour, Policy{}, Alert, "recovery login from 192.0.2.7"},
		{"killed", sess("3", "alice", jump), 0, Policy{Killed: map[string]bool{"3": true}, Approved: map[string]bool{"3": true}}, End, "killed"},
		{"auto from jump", sess("4", "xdrops", jump), time.Hour, Policy{}, Keep, ""},
		{"auto elsewhere", sess("4", "xdrops", other), 0, Policy{}, Pending, ""},
		{"new user", sess("5", "evil", jump), 0, Policy{}, End, "user not in baseline"},
		{"new user paused", sess("5", "evil", jump), 0, Policy{Paused: true}, Alert, "user not in baseline"},
		{"new user approved", sess("5", "evil", jump), 0, Policy{Users: map[string]bool{"evil": true}}, Pending, ""},
		{"approved", sess("6", "alice", jump), time.Hour, Policy{Approved: map[string]bool{"6": true}}, Keep, ""},
		{"paused", sess("7", "alice", jump), time.Hour, Policy{Paused: true}, Keep, "paused"},
		{"pending", sess("8", "root", jump), 89 * time.Second, Policy{}, Pending, ""},
		{"too late", sess("8", "root", jump), 90 * time.Second, Policy{}, End, "not approved within 1m30s"},
		{"tty", Session{ID: "9", User: "evil", Service: "login"}, time.Hour, Policy{}, Keep, ""},
	} {
		row.p.Cfg, row.p.BaseUsers, row.p.Now = c, base, now
		v, why := Judge(row.s, now.Add(-row.first), row.p)
		if v != row.want || !strings.Contains(why, row.why) {
			t.Errorf("%s: got %v %q, want %v %q", row.name, v, why, row.want, row.why)
		}
	}
}
