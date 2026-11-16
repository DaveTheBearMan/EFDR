package controller

import (
	"context"
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
