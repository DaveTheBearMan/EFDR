package console

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/breakglass"
	"xdr/internal/controller"
	"xdr/internal/creds"
	"xdr/internal/fleet"
	"xdr/internal/fleettest"
	"xdr/internal/incident"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

func start(t *testing.T, dir, listen string) (*embed.Etcd, *clientv3.Client) {
	t.Helper()
	e, c, err := controller.StartEtcd(dir, listen)
	if err != nil {
		t.Fatal(err)
	}
	hosts, _ := pki.Hosts(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.Bootstrap(ctx, c, hosts); err != nil {
		t.Fatal(err)
	}
	return e, c
}

func actionsRig(t *testing.T) (*Actions, *State, *fleettest.Fleet) {
	t.Helper()
	f := fleettest.New(t, start, "web01")
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
		Cfg: &controller.Config{GrayUsers: []string{"gray1"}, Recovery: "xdrrecover"}, Key: key, State: s, Now: func() time.Time { return t0 }}
	return a, s, f
}

func get(t *testing.T, f *fleettest.Fleet, key string) (string, int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := f.Root.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Kvs) == 0 {
		return "", 0
	}
	return string(r.Kvs[0].Value), r.Kvs[0].ModRevision
}

func TestActions_DecideSession(t *testing.T) {
	a, s, f := actionsRig(t)
	s.Feed(inc("web01", "session-pending", "alert", 0, func(i *incident.Incident) { i.User, i.Detail = "alice", "session 7 from 192.0.2.7 (ends in 1m30s)" }))
	s.Feed(inc("web01", "session-pending", "alert", 0, func(i *incident.Incident) { i.User, i.Detail = "bob", "session 8 from 192.0.2.7 (ends in 1m30s)" }))
	ctx := context.Background()
	if err := a.Decide(ctx, "s:web01:7", "approve"); err != nil {
		t.Fatal(err)
	}
	v, rev := get(t, f, fleet.To("web01")+"session/7")
	var got struct {
		Verdict string
		At      int64
	}
	if json.Unmarshal([]byte(v), &got) != nil || got.Verdict != "approve" || got.At != t0.Unix() {
		t.Fatalf("order %q", v)
	}
	if err := a.Decide(ctx, "s:web01:7", "approve"); !errors.Is(err, ErrHandled) {
		t.Fatalf("second time: %v", err)
	}
	if _, rev2 := get(t, f, fleet.To("web01")+"session/7"); rev2 != rev {
		t.Fatal("a second order was put")
	}
	if err := a.Decide(ctx, "s:web01:8", "kill"); err != nil {
		t.Fatal(err)
	}
	if v, _ := get(t, f, fleet.To("web01")+"session/8"); !strings.Contains(v, `"kill"`) {
		t.Fatalf("kill order %q", v)
	}
	if err := a.Decide(ctx, "s:web01:404", "approve"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestActions_GrayRefused(t *testing.T) {
	a, s, f := actionsRig(t)
	s.Feed(inc("web01", "user-new", "alert", 0, func(i *incident.Incident) { i.User = "gray1" }))
	err := a.Decide(context.Background(), "u:web01:gray1", "approve")
	if err == nil || !strings.Contains(err.Error(), "protected account") {
		t.Fatalf("err = %v", err)
	}
	if v, _ := get(t, f, fleet.To("web01")+"user/gray1"); v != "" {
		t.Fatalf("an order was put: %q", v)
	}
	if _, ok := s.Peek("u:web01:gray1"); !ok {
		t.Fatal("a refused approval was marked handled")
	}
}

func TestActions_FileAndProc(t *testing.T) {
	a, s, f := actionsRig(t)
	s.Feed(inc("web01", "file-drift", "alert", 0, func(i *incident.Incident) {
		i.Path, i.SHA256, i.Detail = "/etc/cron.d/evil", "0123456789abcdef", "cron added: new file (sha256 0123456789ab)"
	}))
	s.Feed(inc("web01", "service-shell", "held", time.Second, func(i *incident.Incident) {
		i.PID, i.Exe, i.SHA256 = 950, "/usr/bin/dash", "abcdef0123456789abcdef"
	}))
	ctx := context.Background()
	if err := a.Decide(ctx, "f:web01:"+fleet.FileID("/etc/cron.d/evil"), "kill"); err == nil {
		t.Fatal("an action the approval does not offer was accepted")
	}
	if err := a.Decide(ctx, "f:web01:"+fleet.FileID("/etc/cron.d/evil"), "remove"); err != nil {
		t.Fatal(err)
	}
	if v, _ := get(t, f, fleet.To("web01")+"file/"+fleet.FileID("/etc/cron.d/evil")); !strings.Contains(v, `"remove"`) {
		t.Fatalf("file order %q", v)
	}
	if err := a.Decide(ctx, "p:web01:950:abcdef012345", "kill"); err != nil {
		t.Fatal(err)
	}
	if v, _ := get(t, f, fleet.To("web01")+"proc/950"); !strings.Contains(v, `"kill"`) || !strings.Contains(v, "abcdef0123456789abcdef") {
		t.Fatalf("proc order %q", v)
	}
	s.Feed(inc("web01", "service-shell", "held", 2*time.Second, func(i *incident.Incident) {
		i.PID, i.Exe, i.SHA256 = 951, "/usr/bin/dash", "fedcba9876543210fedcba"
	}))
	if err := a.Decide(ctx, "p:web01:951:fedcba987654", "ignore"); err != nil {
		t.Fatal(err)
	}
	if v, _ := get(t, f, fleet.To("web01")+"proc/951"); v != "" {
		t.Fatalf("ignore put an order: %q", v)
	}
}

func TestActions_RotateStoreBeforePut(t *testing.T) {
	a, _, f := actionsRig(t)
	down := a.Client
	a.Client = func() (*clientv3.Client, error) { return nil, errors.New("etcd is down") }
	if _, err := a.Rotate(context.Background(), "web01", []string{"alice"}, nil); err == nil || !strings.Contains(err.Error(), "stored, not sent") {
		t.Fatalf("err = %v", err)
	}
	store, _ := creds.Load(f.Dir)
	if len(store.Hosts["web01"]["alice"].Password) != 20 {
		t.Fatalf("store %+v", store.Hosts)
	}
	a.Client = down
	out, err := a.Rotate(context.Background(), "web01", []string{"alice", "bob"}, []string{"bob"})
	if err != nil || len(out) != 2 {
		t.Fatalf("%v %v", out, err)
	}
	v, _ := get(t, f, fleet.To("web01")+"creds")
	for _, r := range out {
		if strings.Contains(v, r.Password) {
			t.Fatalf("a password is in the etcd order: %s", v)
		}
	}
	if _, err := a.Rotate(context.Background(), "web01", []string{"gray1"}, nil); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("gray: %v", err)
	}
	entries := a.Entries()
	if len(entries) != 2 || entries[0].Account != "alice" || entries[1].Service != "samba" {
		t.Fatalf("entries %+v", entries)
	}
	if blk := a.Creds(); !strings.Contains(blk, "web01\tssh\talice\t") || strings.Count(blk, "\n") != 2 {
		t.Fatalf("block %q", blk)
	}
}

func TestActions_BreakglassUninstall(t *testing.T) {
	a, _, f := actionsRig(t)
	tok, err := a.Breakglass("web01", "uninstall", 5)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := rules.LoadPublic(filepath.Join(f.Dir, "rules.pub"))
	if got, err := breakglass.Parse(tok, pub); err != nil || got.Action != "uninstall" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := a.Breakglass("web01", "uninstall", 1441); err == nil {
		t.Fatal("too long accepted")
	}
}

func TestActions_Breakglass(t *testing.T) {
	a, _, f := actionsRig(t)
	tok, err := a.Breakglass("web01", "pause", 60)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := rules.LoadPublic(filepath.Join(f.Dir, "rules.pub"))
	got, err := breakglass.Parse(tok, pub)
	if err != nil || got.Host != "web01" || got.Action != "pause" || !got.NotBefore.Equal(t0) || !got.Expires.Equal(t0.Add(time.Hour)) {
		t.Fatalf("%+v %v", got, err)
	}
	if got.Valid("web01", t0.Add(time.Minute)) != nil {
		t.Fatal("not valid in its window")
	}
	for name, args := range map[string][3]any{
		"not enrolled": {"nope", "pause", 60},
		"zero minutes": {"web01", "pause", 0},
		"too long":     {"web01", "pause", 2000},
		"bad action":   {"web01", "root-shell", 60},
	} {
		if _, err := a.Breakglass(args[0].(string), args[1].(string), args[2].(int)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Two rotations while the agent is away must both reach it: the standing
// order is one key, so the second carries the first's accounts too.
func TestActions_RotateMergesTheStandingSet(t *testing.T) {
	a, _, f := actionsRig(t)
	ctx := context.Background()
	if _, err := a.Rotate(ctx, "web01", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	first, _ := get(t, f, fleet.To("web01")+"creds")
	if _, err := a.Rotate(ctx, "web01", []string{"bob"}, nil); err != nil {
		t.Fatal(err)
	}
	second, _ := get(t, f, fleet.To("web01")+"creds")
	var s1, s2 creds.Set
	json.Unmarshal([]byte(first), &s1)
	json.Unmarshal([]byte(second), &s2)
	if s2.ID == s1.ID || len(s2.Users) != 2 || s2.Users["alice"].Hash != s1.Users["alice"].Hash || s2.Users["bob"].Hash == "" {
		t.Fatalf("first %+v second %+v", s1, s2)
	}
	// Rotating alice again replaces her entry, not bob's.
	if _, err := a.Rotate(ctx, "web01", []string{"alice"}, nil); err != nil {
		t.Fatal(err)
	}
	third, _ := get(t, f, fleet.To("web01")+"creds")
	var s3 creds.Set
	json.Unmarshal([]byte(third), &s3)
	if s3.Users["alice"].Hash == s1.Users["alice"].Hash || s3.Users["bob"].Hash != s2.Users["bob"].Hash {
		t.Fatalf("third %+v", s3)
	}
}

// Rotations from two tabs, or a tab and the command line, race on the store
// and the order: afterwards every account's stored password must be the one
// its hash in the order was made from.
func TestActions_ConcurrentRotationsAgree(t *testing.T) {
	a, _, f := actionsRig(t)
	var wg sync.WaitGroup
	users := []string{"u1", "u2", "u3", "u4", "u5", "u6"}
	for _, u := range users {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			if _, err := a.Rotate(context.Background(), "web01", []string{u}, nil); err != nil {
				t.Errorf("%s: %v", u, err)
			}
		}(u)
	}
	wg.Wait()
	v, _ := get(t, f, fleet.To("web01")+"creds")
	var set creds.Set
	json.Unmarshal([]byte(v), &set)
	store, err := creds.Load(f.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		hash := set.Users[u].Hash
		pw := store.Hosts["web01"][u].Password
		parts := strings.Split(hash, "$") // "", "6", salt, sum
		if len(parts) != 4 || pw == "" || creds.SHA512Crypt(pw, parts[2], 5000) != hash {
			t.Errorf("%s: the stored password is not the one the order was made from (hash %q, stored %q)", u, hash, pw)
		}
	}
}

// Every console action is an incident in the controller's log: who (the
// source address), what, and for which host.
func TestServer_ActionsAudited(t *testing.T) {
	a, s, _ := actionsRig(t)
	if err := SetPassword(a.Dir, "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	var got []incident.Incident
	srv := NewServer(a.Dir, func() View { return s.View(nil, nil) }, a, func() time.Time { return t0 }, io.Discard)
	srv.Audit = func(in incident.Incident) { got = append(got, in) }
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	post := func(path, cookie string, body any) *http.Response {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewReader(b))
		req.Header.Set("X-XDR", "1")
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
	for _, c := range post("/login", "", map[string]string{"password": "correct horse battery"}).Cookies() {
		tok = c.Value
	}
	s.Feed(inc("web01", "session-pending", "alert", 0, func(i *incident.Incident) { i.User, i.Detail = "alice", "session 7 from 192.0.2.7 (ends in 1m30s)" }))
	if resp := post("/api/decide", tok, map[string]string{"id": "s:web01:7", "action": "approve"}); resp.StatusCode != 204 {
		t.Fatalf("decide: %d", resp.StatusCode)
	}
	if resp := post("/api/breakglass", tok, map[string]any{"host": "web01", "action": "pause", "minutes": 30}); resp.StatusCode != 200 {
		t.Fatalf("breakglass: %d", resp.StatusCode)
	}
	if len(got) != 2 {
		t.Fatalf("%d audit incidents: %+v", len(got), got)
	}
	for i, want := range []string{"approve", "pause"} {
		in := got[i]
		if in.Kind != "console-action" || in.Host != "web01" || !strings.Contains(in.Detail, "127.0.0.1") || !strings.Contains(in.Detail, want) {
			t.Errorf("audit %d: %+v", i, in)
		}
	}
}

// A gray account is alert-only everywhere: the controller refuses a kill
// order for its process before any agent must.
func TestActions_ProcKillOfGrayRefused(t *testing.T) {
	a, s, f := actionsRig(t)
	s.Feed(inc("web01", "service-shell", "held", time.Second, func(i *incident.Incident) {
		i.PID, i.Exe, i.SHA256, i.User = 960, "/usr/bin/dash", "abcdef0123456789abcdef", "gray1"
	}))
	if err := a.Decide(context.Background(), "p:web01:960:abcdef012345", "kill"); err == nil {
		t.Fatal("a kill of a gray account's process was accepted")
	}
	if v, _ := get(t, f, fleet.To("web01")+"proc/960"); v != "" {
		t.Fatalf("order put: %q", v)
	}
	if _, ok := s.Peek("p:web01:960:abcdef012345"); !ok {
		t.Fatal("a refused approval was marked handled")
	}
}
