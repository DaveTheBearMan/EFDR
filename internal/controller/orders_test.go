package controller

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"xdr/internal/fleet"
	"xdr/internal/fleettest"
)

func TestPutOrder_Key(t *testing.T) {
	f := fleettest.New(t, start, "web01")
	t.Cleanup(f.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := PutOrder(ctx, f.Root, "web01", "session", "7", map[string]string{"verdict": "approve"}); err != nil {
		t.Fatal(err)
	}
	if err := PutOrder(ctx, f.Root, "web01", "creds", "", map[string]string{"ID": "x"}); err != nil {
		t.Fatal(err)
	}
	r, err := f.Root.Get(ctx, fleet.To("web01")+"session/7")
	if err != nil || len(r.Kvs) != 1 || string(r.Kvs[0].Value) != `{"verdict":"approve"}` {
		t.Fatalf("%v %v", r, err)
	}
	if r, _ := f.Root.Get(ctx, fleet.To("web01")+"creds"); len(r.Kvs) != 1 {
		t.Fatal("creds not at its key")
	}
	if err := PutOrder(ctx, f.Root, "web01", "creds", "", string(make([]byte, 70<<10))); err == nil {
		t.Fatal("oversized order put")
	}
}

func TestPutMode_OneHostAndAll(t *testing.T) {
	f := fleettest.New(t, start, "web01", "db01")
	t.Cleanup(f.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	at := time.Date(2026, 11, 16, 12, 0, 0, 5, time.UTC)
	got := func(host string) (Mode, bool) {
		t.Helper()
		r, err := f.Root.Get(ctx, fleet.To(host)+"mode")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Kvs) == 0 {
			return Mode{}, false
		}
		var m Mode
		if err := json.Unmarshal(r.Kvs[0].Value, &m); err != nil {
			t.Fatalf("%s: %q", host, r.Kvs[0].Value)
		}
		return m, true
	}
	hosts, err := PutMode(ctx, f.Root, f.Dir, []string{"web01"}, Mode{Kill: true, At: at, By: "console"})
	if err != nil || !slices.Equal(hosts, []string{"web01"}) {
		t.Fatalf("%v %v", hosts, err)
	}
	if m, ok := got("web01"); !ok || !m.Kill || !m.At.Equal(at) || m.By != "console" {
		t.Fatalf("web01: %+v %v", m, ok)
	}
	if _, ok := got("db01"); ok {
		t.Fatal("an order for one host reached another")
	}
	hosts, err = PutMode(ctx, f.Root, f.Dir, nil, Mode{Kill: false, At: at.Add(time.Second)})
	if err != nil || !slices.Equal(hosts, []string{"db01", "web01"}) {
		t.Fatalf("all: %v %v", hosts, err)
	}
	for _, h := range []string{"web01", "db01"} {
		if m, ok := got(h); !ok || m.Kill || !m.At.Equal(at.Add(time.Second)) {
			t.Fatalf("%s: %+v", h, m)
		}
	}
	if _, err := PutMode(ctx, f.Root, f.Dir, []string{"nope"}, Mode{Kill: true, At: at}); err == nil {
		t.Fatal("a host that is not enrolled")
	}
	if _, err := PutMode(ctx, f.Root, f.Dir, []string{"web01"}, Mode{Kill: true}); err == nil {
		t.Fatal("an order with no time")
	}
}
