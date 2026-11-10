package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"xdr/internal/config"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/testfs"
)

const exampleConfig = "../../deploy/agent.example.json"

func TestFwPrint(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"fw", "print", "--config", exampleConfig}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	found := false
	for _, line := range strings.Split(out.String(), "\n") {
		found = found || strings.Contains(line, "tcp dport 22 accept")
	}
	if !found {
		t.Fatalf("no ssh rule in:\n%s", out.String())
	}
}

func TestFw_BadConfigExits2(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "agent.json", `{"host":"web01"}`, 0o600)
	for _, verb := range []string{"print", "apply", "try"} {
		var out, errb bytes.Buffer
		code := Run([]string{"fw", verb, "--config", filepath.Join(root, "agent.json")}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "jump") || out.Len() != 0 {
			t.Fatalf("fw %s: exit %d, stdout %q, stderr %q", verb, code, out.String(), errb.String())
		}
	}
}

func TestFw_UnknownVerb(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"fw", "flush", "--config", exampleConfig}, &out, &errb); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestPrint_EscapesControlBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	l, err := incident.Open(path, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, in := range []incident.Incident{
		{Time: when, Kind: "revshell-stdio", Action: "killed", Severity: model.SevCritical, PID: 4242,
			Exe: "/tmp/\x1b[31mx\n", Remote: &incident.Endpoint{Addr: "203.0.113.9", Port: 4444, Proto: "tcp"}, Detail: "shell\ton\ra socket"},
		{Time: when, Kind: "listener\n", Action: "alert", Severity: model.SevHigh, PID: 7, Exe: "/usr/bin/nc", Detail: "tcp/9001"},
	} {
		if _, err := l.Add(in); err != nil {
			t.Fatal(err)
		}
	}
	l.Close()
	var out, errb bytes.Buffer
	if code := Run([]string{"incidents", "--file", path}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "2026-11-10T12:00:00Z CRITICAL revshell-stdio killed pid=4242 /tmp/\\x1b[31mx\\n → 203.0.113.9:4444 shell\\ton\\ra socket\n" +
		"2026-11-10T12:00:00Z HIGH listener\\n alert pid=7 /usr/bin/nc tcp/9001\n"
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestIncidents_NoLogYet(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"incidents", "--file", filepath.Join(t.TempDir(), "none.jsonl")}, &out, &errb); code != 0 || out.Len() != 0 {
		t.Fatalf("exit %d, out %q, err %q", code, out.String(), errb.String())
	}
}

func TestListenersCmd(t *testing.T) {
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	lo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lo.Close()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := Run([]string{"listeners"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var got []config.Listener
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	tcp := config.Listener{Proto: "tcp", Port: uint16(l.Addr().(*net.TCPAddr).Port), Exe: exe}
	udp := config.Listener{Proto: "udp", Port: uint16(lo.LocalAddr().(*net.UDPAddr).Port), Exe: exe}
	if !slices.Contains(got, tcp) || !slices.Contains(got, udp) {
		t.Fatalf("want %+v and %+v in\n%s", tcp, udp, out.String())
	}

	// With a config, a scored port is left out.
	cfg := filepath.Join(t.TempDir(), "agent.json")
	body := fmt.Sprintf(`{"host":"web01","jump":["192.0.2.7/32"],"scored":[{"proto":"tcp","port":%d}]}`, tcp.Port)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Run([]string{"listeners", "--config", cfg}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got = nil
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, tcp) || !slices.Contains(got, udp) {
		t.Fatalf("scored port listed, or the other one lost:\n%s", out.String())
	}
}

func TestAgentCmd_NeedsConfig(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"agent"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--config") {
		t.Fatalf("exit %d, err %q", code, errb.String())
	}
	if code := Run([]string{"agent", "--config", filepath.Join(t.TempDir(), "none.json")}, &out, &errb); code != 2 {
		t.Fatalf("missing config: exit %d", code)
	}
}
