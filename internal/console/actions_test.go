package console

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
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
