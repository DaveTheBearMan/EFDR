package console

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/controller"
	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/incident"
	"xdr/internal/rules"
)

// modeRig is the actions over three enrolled hosts, mail01 disabled.
func modeRig(t *testing.T) (*Actions, *State, *fleettest.Fleet) {
	t.Helper()
	f := fleettest.New(t, start, "web01", "db01", "mail01")
	t.Cleanup(f.Stop)
	s, err := NewState(f.Dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	key, err := rules.LoadPrivate(filepath.Join(f.Dir, "rules.key"))
	if err != nil {
		t.Fatal(err)
	}
	a := &Actions{Dir: f.Dir, Client: func() (*clientv3.Client, error) { return f.Root, nil },
		Cfg: &controller.Config{GrayUsers: []string{"gray1"}}, Key: key, State: s, Now: func() time.Time { return t0 },
		Hosts: func() []controller.HostStatus {
			return []controller.HostStatus{{Name: "db01", Seen: true}, {Name: "mail01", Seen: true, Disabled: true}, {Name: "web01", Seen: true}}
		}}
	return a, s, f
}

func modeAt(t *testing.T, f *fleettest.Fleet, host string) (controller.Mode, bool) {
	t.Helper()
	v, _ := get(t, f, fleet.To(host)+"mode")
	if v == "" {
		return controller.Mode{}, false
	}
	var m controller.Mode
	if err := json.Unmarshal([]byte(v), &m); err != nil {
		t.Fatalf("%s: %q", host, v)
	}
	return m, true
}

func TestActions_Mode(t *testing.T) {
	a, _, f := modeRig(t)
	ctx := context.Background()
	hosts, err := a.Mode(ctx, "web01", true, "console, from 192.0.2.7")
	if err != nil || len(hosts) != 1 || hosts[0] != "web01" {
		t.Fatalf("%v %v", hosts, err)
	}
	if m, ok := modeAt(t, f, "web01"); !ok || !m.Kill || !m.At.Equal(t0) || !strings.Contains(m.By, "192.0.2.7") {
		t.Fatalf("web01 order: %+v", m)
	}
	if _, ok := modeAt(t, f, "db01"); ok {
		t.Fatal("db01 got web01's order")
	}
	for _, bad := range []string{"", "Web01", "web01;rm", "../web01", "nope", "mail01"} {
		if _, err := a.Mode(ctx, bad, false, "console"); err == nil {
			t.Errorf("host %q accepted", bad)
		}
	}
	if m, _ := modeAt(t, f, "web01"); !m.Kill {
		t.Fatal("a refused order was put")
	}
	if _, ok := modeAt(t, f, "mail01"); ok {
		t.Fatal("an order reached a disabled host")
	}
	// All hosts: every enrolled one the controller has not disabled.
	hosts, err = a.Mode(ctx, AllHosts, false, "console")
	if err != nil || strings.Join(hosts, ",") != "db01,web01" {
		t.Fatalf("all: %v %v", hosts, err)
	}
	for _, h := range []string{"web01", "db01"} {
		if m, ok := modeAt(t, f, h); !ok || m.Kill {
			t.Fatalf("%s after all-off: %+v", h, m)
		}
	}
	if _, ok := modeAt(t, f, "mail01"); ok {
		t.Fatal("all reached a disabled host")
	}
}

// The toggle is a POST with the header, and an audited console action.
func TestServer_ModeAudited(t *testing.T) {
	a, s, f := modeRig(t)
	if err := SetPassword(a.Dir, goodPassword); err != nil {
		t.Fatal(err)
	}
	var got []incident.Incident
	srv := NewServer(a.Dir, func() View { return s.View(a.Hosts(), nil) }, a, func() time.Time { return t0 }, io.Discard)
	srv.Audit = func(in incident.Incident) { got = append(got, in) }
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	post := func(path, cookie string, body any, header bool) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
		if header {
			req.Header.Set("X-XDR", "1")
		}
		if cookie != "" {
			req.Header.Set("Cookie", "xdr="+cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	var tok string
	for _, c := range post("/login", "", map[string]string{"password": goodPassword}, false).Cookies() {
		tok = c.Value
	}
	if resp := post("/api/mode", "", map[string]any{"host": "web01", "kill": true}, true); resp.StatusCode != 401 {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
	if resp := post("/api/mode", tok, map[string]any{"host": "web01", "kill": true}, false); resp.StatusCode != 403 {
		t.Fatalf("no header: %d", resp.StatusCode)
	}
	if _, ok := modeAt(t, f, "web01"); ok {
		t.Fatal("an order was put without the header")
	}
	if resp := post("/api/mode", tok, map[string]any{"host": "web01", "kill": true}, true); resp.StatusCode != 204 {
		t.Fatalf("mode: %d", resp.StatusCode)
	}
	if resp := post("/api/mode", tok, map[string]any{"host": "*", "kill": false}, true); resp.StatusCode != 204 {
		t.Fatalf("mode all: %d", resp.StatusCode)
	}
	if resp := post("/api/mode", tok, map[string]any{"host": "mail01", "kill": true}, true); resp.StatusCode != 400 {
		t.Fatalf("disabled host: %d", resp.StatusCode)
	}
	if resp := post("/api/mode", tok, map[string]any{"host": "web01"}, true); resp.StatusCode != 400 {
		t.Fatalf("no kill field: %d", resp.StatusCode)
	}
	if len(got) != 2 {
		t.Fatalf("%d audit incidents: %+v", len(got), got)
	}
	for i, want := range []struct{ host, what string }{{"web01", "kill on"}, {"", "kill off for every host"}} {
		in := got[i]
		if in.Kind != "console-action" || in.Host != want.host || !strings.Contains(in.Detail, "127.0.0.1") || !strings.Contains(in.Detail, want.what) {
			t.Errorf("audit %d: %+v", i, in)
		}
	}
	if m, _ := modeAt(t, f, "web01"); !strings.Contains(m.By, "127.0.0.1") {
		t.Errorf("the order does not say who: %+v", m)
	}
}

// Each host's row says what its agent last reported of the switch:
// nothing (the config decides) until a mode incident.
func TestState_HostKill(t *testing.T) {
	s, _, _ := newState(t)
	hosts := []controller.HostStatus{{Name: "web01", Seen: true}, {Name: "db01", Seen: true}}
	kill := func(v View, h string) string {
		for _, r := range v.Hosts {
			if r.Name == h {
				return r.Kill
			}
		}
		t.Fatalf("no row %s", h)
		return ""
	}
	if v := s.View(hosts, nil); kill(v, "web01") != "" || kill(v, "db01") != "" {
		t.Fatalf("before any order: %+v", v.Hosts)
	}
	s.Feed(inc("web01", "mode", "kill-off", 0, nil))
	s.Feed(inc("db01", "mode", "kill-on", time.Second, nil))
	if v := s.View(hosts, nil); kill(v, "web01") != "off" || kill(v, "db01") != "on" {
		t.Fatalf("after orders: %+v", v.Hosts)
	}
	s.Feed(inc("web01", "mode", "kill-on", 2*time.Second, nil))
	// A refused order changes nothing.
	s.Feed(inc("web01", "mode-refused", "alert", 3*time.Second, nil))
	if v := s.View(hosts, nil); kill(v, "web01") != "on" {
		t.Fatalf("after the second order: %+v", v.Hosts)
	}
	// It outlasts the incidents it came from.
	for i := 0; i < maxIncidents+10; i++ {
		s.Feed(inc("db01", "egress", "alert", time.Duration(4+i)*time.Second, nil))
	}
	if v := s.View(hosts, nil); kill(v, "web01") != "on" || kill(v, "db01") != "on" {
		t.Fatalf("after the ring turned over: %+v", v.Hosts)
	}
}
