package agent

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"xdr/internal/config"
	"xdr/internal/fleet"
	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/mesh"
	"xdr/internal/model"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

const (
	huntQueue    = 16   // hunts waiting to be searched
	huntsSeen    = 1024 // hunt ids remembered
	perSender    = 30   // hunts searched for one sender per senderWindow
	senderWindow = 10 * time.Minute
	maxHuntText  = 1 << 10
	firstUserUID = 1000 // below it, system and package accounts
)

// meshLink is the agent's view of the peer mesh.
type meshLink interface {
	PushHunt(r *hunt.Request, except netip.Addr)
	PushRules()
}

// hunter runs other boxes' hunts on this one, one at a time.
type hunter struct {
	mu      sync.Mutex
	queue   chan *hunt.Request
	seen    map[string]bool
	order   []string
	senders map[string][]time.Time // searches per sender in the window
	dropped map[string]bool        // senders already told about this window
	fullAt  time.Time              // when a full queue was last reported
}

// full reports whether a full queue should be reported now: once per
// senderWindow.
func (h *hunter) full(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.fullAt.IsZero() && now.Sub(h.fullAt) < senderWindow {
		return false
	}
	h.fullAt = now
	return true
}

func newHunter() *hunter {
	return &hunter{queue: make(chan *hunt.Request, huntQueue), seen: map[string]bool{},
		senders: map[string][]time.Time{}, dropped: map[string]bool{}}
}

// remember marks id seen and reports whether it was new.
func (h *hunter) remember(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[id] {
		return false
	}
	h.seen[id] = true
	h.order = append(h.order, id)
	if len(h.order) > huntsSeen {
		delete(h.seen, h.order[0])
		h.order = h.order[1:]
	}
	return true
}

// admit counts one hunt from sender and reports whether it is within the
// cap, and whether a drop should be reported.
func (h *hunter) admit(sender string, now time.Time) (ok, report bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ts := slices.DeleteFunc(h.senders[sender], func(t time.Time) bool { return now.Sub(t) >= senderWindow })
	if len(ts) == 0 {
		delete(h.dropped, sender)
	}
	if len(ts) >= perSender {
		h.senders[sender] = ts
		report = !h.dropped[sender]
		h.dropped[sender] = true
		return false, report
	}
	h.senders[sender] = append(ts, now)
	return true, false
}

// startHunt sends the hunt an incident starts to the fleet and the peers.
// This box acted on the incident itself, so it does not search for it.
// The caller holds a.mu.
func (a *agent) startHunt(in incident.Incident, baseExe bool) {
	if a.fleet == nil || a.hunts == nil {
		return
	}
	// Base, gray-team and system accounts (packages add those) are on
	// every box: as indicators they would hit everywhere.
	users := map[string]bool{}
	if a.pol.Base != nil {
		for _, acct := range a.pol.Base.Accounts {
			users[acct.Name] = true
		}
	}
	for _, u := range a.cfg.GrayUsers {
		users[u] = true
	}
	if in.UID < firstUserUID {
		users[in.User] = true
	}
	r := hunt.FromIncident(in, hunt.Base{
		Exe:  func(string, string) bool { return baseExe },
		User: func(u string) bool { return users[u] },
	})
	if r == nil {
		return
	}
	a.hunts.remember(r.ID)
	a.fleet.PutHunt(r)
	if a.mesh != nil {
		a.mesh.PushHunt(r, netip.Addr{})
	}
}

// offerHunt queues a hunt another box started, heard over via ("etcd" or
// a peer). It never blocks.
func (a *agent) offerHunt(r *hunt.Request, via string) {
	h := a.hunts
	if h == nil || r.From == a.cfg.Host || !h.remember(r.ID) {
		return
	}
	drop := func(why string) {
		a.recordLocked(incident.Incident{Kind: "hunt-dropped", Action: "alert", Severity: model.SevMedium, Hunt: r.ID,
			Detail: fmt.Sprintf("hunt %s from %s via %s: %s", r.ID, r.From, via, why)})
	}
	// etcd vouches for From; over the mesh only the relaying peer is
	// known, so the cap is on it.
	sender := r.From
	if strings.HasPrefix(via, "peer ") {
		sender = via
	}
	ok, report := h.admit(sender, a.now())
	if !ok {
		if report {
			drop(fmt.Sprintf("more than %d hunts from %s in %s", perSender, sender, senderWindow))
		}
		return
	}
	select {
	case h.queue <- r:
	default:
		if h.full(a.now()) {
			drop(fmt.Sprintf("queue full (told once per %s)", senderWindow))
		}
	}
}

// searchBox is the search a hunt runs here: this box's files and a fresh
// process snapshot.
func (a *agent) searchBox(ctx context.Context, r *hunt.Request) hunt.Result {
	snap, _ := a.read()
	a.mu.Lock()
	hash := a.pol.Hash
	a.mu.Unlock()
	return hunt.Search(ctx, a.root, r, snap, hash, hunt.DefaultBudget)
}

// startHunts runs queued hunts, one at a time, until ctx is done.
func (a *agent) startHunts(ctx context.Context) (stop func()) {
	if a.hunts == nil {
		a.hunts = newHunter()
	}
	if a.search == nil {
		a.search = a.searchBox
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case r := <-a.hunts.queue:
				a.runHunt(ctx, r)
			}
		}
	}()
	return func() { <-done }
}

// dropDirs are where an attacker's own files land. Only a variant there is
// proposed: a hunt may name any path, and a "variant" of a real service
// binary elsewhere would have it ruled fleet-wide.
var dropDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/", "/run/user/"}

func inDropDir(p string) bool {
	return slices.ContainsFunc(dropDirs, func(d string) bool { return strings.HasPrefix(p, d) })
}

// runHunt searches for r and records what came of it. A file at a hunted
// path with a new hash is a variant, proposed as a hash rule when it is in
// a drop directory.
func (a *agent) runHunt(ctx context.Context, r *hunt.Request) {
	res := a.search(ctx, r)
	in := incident.Incident{Kind: "hunt-clean", Action: "alert", Severity: model.SevInfo, Hunt: r.ID,
		Detail: fmt.Sprintf("hunt %s from %s: nothing found", r.ID, r.From)}
	hunted := map[string]bool{}
	for _, f := range r.IOC.Files {
		hunted[f.SHA256] = true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var variants []rules.Rule
	if len(res.Hits) > 0 {
		var say []string
		for _, h := range res.Hits {
			s := h.Kind + " " + h.What
			if h.PID != 0 {
				s += fmt.Sprintf(" (pid %d)", h.PID)
			}
			say = append(say, s)
			if h.Kind == "path" && h.SHA256 != "" && !hunted[h.SHA256] && inDropDir(h.Path) && (a.baseHash == nil || !a.baseHash(h.SHA256)) {
				v := rules.Rule{Kind: "hash", SHA256: h.SHA256, Exe: h.Path, From: a.cfg.Host, Seen: a.now(),
					Detail: fmt.Sprintf("hunt %s from %s: variant at %s", r.ID, r.From, h.Path)}
				v.SetID()
				variants = append(variants, v)
			}
		}
		in.Kind, in.Severity = "hunt-hit", model.SevHigh
		in.Detail = fmt.Sprintf("hunt %s from %s: %s", r.ID, r.From, strings.Join(say, "; "))
	}
	if res.Partial != "" {
		in.Detail += " (hunt-partial: " + res.Partial + ")"
	}
	in.Detail = rules.Cut(in.Detail, maxHuntText)
	a.record(in)
	if len(variants) > 0 && a.fleet != nil {
		a.fleet.Propose(variants)
	}
}

// meshAddrs is where the mesh listens, and the peers it links to: the
// first peers entry that is this box's own address (or every address,
// when none is), and the rest, all on port.
func meshAddrs(peers []config.Net, port uint16, local func(netip.Addr) bool) (netip.AddrPort, []netip.AddrPort) {
	listen := netip.AddrPortFrom(netip.IPv6Unspecified(), port)
	var out []netip.AddrPort
	found := false
	for _, n := range peers {
		a := n.Addr().Unmap()
		switch {
		case local(a) && !found:
			listen, found = netip.AddrPortFrom(a, port), true
		case local(a):
		default:
			out = append(out, netip.AddrPortFrom(a, port))
		}
	}
	return listen, out
}

// newMesh sets up the peer mesh over f's rule set and returns what starts
// it; its goroutines end with ctx. On a setup failure the agent says so
// and runs without it.
func (a *agent) newMesh(ctx context.Context, cfg *config.Config, f *fleet.Client) (run func()) {
	dir := cfg.Fleet.Dir
	srv, cli, err := pki.PeerTLS(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "host.pem"), filepath.Join(dir, "host-key.pem"), cfg.Host)
	if err != nil {
		a.recordLocked(incident.Incident{Kind: "fleet", Action: "alert", Severity: model.SevHigh, Detail: "no peer mesh: " + err.Error()})
		return func() {}
	}
	listen, peers := meshAddrs(cfg.Peers, cfg.Mesh.Port, a.pol.Local)
	// The mesh may report while the agent's lock is held (a full queue
	// on a hunt pushed from handle): its incidents go through a queue.
	report, stopReport := async(a.recordLocked, 64)
	m := mesh.New(mesh.Config{Host: cfg.Host, Listen: listen, Peers: peers, ServerTLS: srv, ClientTLS: cli, Rules: f,
		OnHunt:     func(r *hunt.Request, from netip.Addr) { a.offerHunt(r, "peer "+from.String()) },
		OnIncident: report,
	})
	a.mesh = m
	return func() {
		go func() {
			defer stopReport()
			if err := m.Run(ctx); err != nil {
				a.recordLocked(incident.Incident{Kind: "fleet", Action: "alert", Severity: model.SevHigh, Detail: "peer mesh: " + err.Error()})
			}
		}()
	}
}
