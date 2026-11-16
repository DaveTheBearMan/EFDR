package controller

import (
	"testing"

	"xdr/internal/fleettest"
)

func TestHosts_Status(t *testing.T) {
	f := fleettest.New(t, start, "web01", "db01")
	t.Cleanup(f.Stop)
	r := run(t, f, nil)
	got := r.ctl.Hosts()
	if len(got) != 2 || got[0].Name != "db01" || got[1].Name != "web01" || got[0].Seen || got[1].Seen {
		t.Fatalf("before any beat: %+v", got)
	}
	r.ctl.heartbeat("web01", true)
	hs := r.ctl.Hosts()
	if !hs[1].Seen || hs[1].Silent || hs[1].Last.IsZero() {
		t.Fatalf("web01 after a beat: %+v", hs[1])
	}
	r.ctl.heartbeat("web01", false)
	if hs = r.ctl.Hosts(); !hs[1].Silent {
		t.Fatalf("web01 after its lease went: %+v", hs[1])
	}
}
