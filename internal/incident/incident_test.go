package incident

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xdr/internal/model"
)

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// clock is a Log's time source the test moves by hand.
type clock struct{ now time.Time }

func open(t *testing.T) (*Log, *clock, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xdr", "incidents.jsonl")
	l, err := Open(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	c := &clock{t0}
	l.now = func() time.Time { return c.now }
	return l, c, path
}

func add(t *testing.T, l *Log, in Incident) bool {
	t.Helper()
	written, err := l.Add(in)
	if err != nil {
		t.Fatal(err)
	}
	return written
}

func readAll(t *testing.T, path string) []Incident {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ins, err := Read(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return ins
}

func revshell() Incident {
	return Incident{
		Host: "web01", Kind: "revshell-stdio", Action: "killed", Severity: model.SevCritical,
		PID: 4242, UID: 33, User: "www-data", Comm: "sh", Exe: "/usr/bin/dash", SHA256: "ab12",
		Cmdline: []string{"sh", "-i"}, Cgroup: "/system.slice/apache2.service", Origin: "unit:apache2.service",
		Chain:  []ProcRef{{PID: 4242, Comm: "sh", Exe: "/usr/bin/dash"}, {PID: 900, Comm: "apache2", Exe: "/usr/sbin/apache2"}},
		Remote: &Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"},
		Detail: "shell with a socket on stdin",
	}
}

func TestLog_RoundTrip(t *testing.T) {
	l, _, path := open(t)
	in := revshell()
	if !add(t, l, in) {
		t.Fatal("not written")
	}
	in.Time, in.Count = t0, 1
	if got := readAll(t, path); len(got) != 1 || !reflect.DeepEqual(got[0], in) {
		t.Fatalf("got  %+v\nwant %+v", got, in)
	}
	raw, _ := os.ReadFile(path)
	for _, key := range []string{`"time":`, `"host":"web01"`, `"severity":"critical"`, `"sha256":"ab12"`, `"remote":{"addr":"203.0.113.9","port":4444,"proto":"tcp"}`, `"chain":[{"pid":4242,"comm":"sh","exe":"/usr/bin/dash"}`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("no %s in %s", key, raw)
		}
	}
}

func TestLog_HostileFieldsOneLine(t *testing.T) {
	l, _, path := open(t)
	in := revshell()
	in.Comm = "a\nb"
	in.Exe = strings.Repeat("é", 4000) // 8000 bytes; the cut must not split a rune
	in.Detail = strings.Repeat("\n", 5000)
	in.Cmdline = []string{"\x1b[2J", "\xff\xfe", strings.Repeat("A", 100_000)}
	in.Chain = []ProcRef{{PID: 1, Comm: strings.Repeat("c", 5000), Exe: strings.Repeat("e", 5000)}}
	in.Remote = &Endpoint{Addr: strings.Repeat("9", 5000), Port: 1, Proto: strings.Repeat("p", 5000)}
	add(t, l, in)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte("\n")); n != 1 || raw[len(raw)-1] != '\n' {
		t.Fatalf("%d newlines in the file", n)
	}
	if bytes.ContainsRune(raw, 0x1b) {
		t.Fatal("raw escape byte in the file")
	}
	got := readAll(t, path)
	if len(got) != 1 {
		t.Fatalf("%d incidents", len(got))
	}
	g := got[0]
	if g.Comm != "a\nb" || g.Cmdline[0] != "\x1b[2J" || len(g.Cmdline) != 3 {
		t.Fatalf("fields changed: %q %q", g.Comm, g.Cmdline[0])
	}
	if in.Remote.Addr != strings.Repeat("9", 5000) || len(in.Cmdline[2]) != 100_000 {
		t.Fatal("Add changed the caller's incident")
	}
	for name, s := range map[string]string{
		"exe": g.Exe, "detail": g.Detail, "arg1": g.Cmdline[1], "arg2": g.Cmdline[2],
		"chain comm": g.Chain[0].Comm, "chain exe": g.Chain[0].Exe, "addr": g.Remote.Addr, "proto": g.Remote.Proto,
	} {
		if len(s) > 4096 || len(s) == 0 {
			t.Errorf("%s: %d bytes", name, len(s))
		}
	}
	if len(g.Exe) != 4096 || len(g.Cmdline[2]) != 4096 {
		t.Errorf("exe %d bytes, arg %d bytes: cut shorter than the limit", len(g.Exe), len(g.Cmdline[2]))
	}
}

func TestLog_Dedupe(t *testing.T) {
	l, c, path := open(t)
	if !add(t, l, revshell()) {
		t.Fatal("first not written")
	}
	for i := 0; i < 2; i++ {
		c.now = c.now.Add(10 * time.Second)
		in := revshell()
		in.PID += i + 1 // a respawned shell is still the same incident
		if add(t, l, in) {
			t.Fatal("repeat inside the window was written")
		}
	}
	if got := readAll(t, path); len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("%+v", got)
	}
	c.now = t0.Add(time.Minute + time.Second)
	if !add(t, l, revshell()) {
		t.Fatal("first after the window not written")
	}
	got := readAll(t, path)
	if len(got) != 2 || got[1].Count != 3 || !got[1].Time.Equal(c.now) {
		t.Fatalf("%+v", got)
	}
	// The count starts again.
	c.now = c.now.Add(2 * time.Minute)
	add(t, l, revshell())
	if got := readAll(t, path); len(got) != 3 || got[2].Count != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestLog_DifferentRemoteNotFolded(t *testing.T) {
	l, _, path := open(t)
	add(t, l, revshell())
	for name, edit := range map[string]func(*Incident){
		"remote port": func(in *Incident) { in.Remote = &Endpoint{Addr: "203.0.113.9", Port: 4445, Proto: "tcp"} },
		"remote addr": func(in *Incident) { in.Remote = &Endpoint{Addr: "203.0.113.10", Port: 4444, Proto: "tcp"} },
		"no remote":   func(in *Incident) { in.Remote = nil },
		"kind":        func(in *Incident) { in.Kind = "egress" },
		"action":      func(in *Incident) { in.Action = "kill-failed" },
		"exe":         func(in *Incident) { in.Exe = "/usr/bin/bash" },
		"uid":         func(in *Incident) { in.UID = 0 },
		"detail":      func(in *Incident) { in.Detail = "other" },
	} {
		in := revshell()
		edit(&in)
		if !add(t, l, in) {
			t.Errorf("%s: folded into a different incident", name)
		}
	}
	if got := readAll(t, path); len(got) != 9 {
		t.Fatalf("%d lines", len(got))
	}
}

func TestLog_Perms(t *testing.T) {
	l, _, path := open(t)
	add(t, l, revshell())
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", p, st.Mode(), err, want)
		}
	}
}

func TestLog_AppendsAcrossReopen(t *testing.T) {
	l, _, path := open(t)
	add(t, l, revshell())
	l.Close()
	l2, err := Open(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	in := revshell()
	in.Kind = "egress"
	add(t, l2, in)
	if got := readAll(t, path); len(got) != 2 || got[0].Kind != "revshell-stdio" || got[1].Kind != "egress" {
		t.Fatalf("%+v", got)
	}
}

func TestRead_BadLinesSkipped(t *testing.T) {
	l, _, path := open(t)
	add(t, l, revshell())
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("not json\n\n{\"kind\":\"torn")
	f.Close()
	b, _ := os.ReadFile(path)
	got, err := Read(bytes.NewReader(b))
	if len(got) != 1 || err == nil || !strings.Contains(err.Error(), "2") {
		t.Fatalf("%d incidents, err %v", len(got), err)
	}
}
