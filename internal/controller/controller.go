package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/fleet"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

const (
	maxValue    = 16 << 10 // the most bytes of one proposal or incident
	hostCap     = 256      // promoted rules per proposing host
	totalCap    = 4096     // promoted rules in all
	silentAfter = 15 * time.Second
	opTimeout   = 5 * time.Second
	writeTries  = 5
	maxSet      = 1 << 20 // below etcd's 1.5 MiB request limit
	floodLimit  = 600
	floodWindow = time.Minute
)

// beat is what the controller knows of one host's heartbeat.
type beat struct {
	seen   bool // a heartbeat was put since the controller started
	silent bool // agent-silent was reported and agent-back not yet
}

// Controller promotes proposed rules to the signed set, takes in the
// agents' incidents and watches their heartbeats.
type Controller struct {
	dir   string
	c     *clientv3.Client
	guard rules.Guard
	key   ed25519.PrivateKey
	log   *incident.Log // nil: incidents are dropped

	now               func() time.Time
	tick, silentAfter time.Duration
	hostCap, totalCap int
	maxSet            int // the most bytes of a published envelope
	floodLimit        int // writes by one host in floodWindow before it is disabled
	mu                sync.Mutex
	set               *rules.Set
	rev               int64 // ModRevision of the rules key; 0: absent
	beats             map[string]*beat
	started           time.Time
	writes            map[string]int // per host, in the window since windowAt
	windowAt          time.Time
	disabled          map[string]bool
	users             map[string]bool // hosts with an etcd user, as far as Run knows
}

// New is a controller over c that continues from the rule set in etcd.
func New(dir string, c *clientv3.Client, g rules.Guard, key ed25519.PrivateKey, log *incident.Log) (*Controller, error) {
	ctl := &Controller{
		dir: dir, c: c, guard: g, key: key, log: log,
		now: time.Now, tick: time.Second, silentAfter: silentAfter,
		hostCap: hostCap, totalCap: totalCap, maxSet: maxSet, floodLimit: floodLimit,
		beats: map[string]*beat{}, writes: map[string]int{}, disabled: map[string]bool{}, users: map[string]bool{},
	}
	// Whatever the baselines say, the controller's own binary, which the
	// operator also runs on the boxes, is never a hash rule.
	if self, err := selfHash(); err == nil {
		base := g.Baseline
		ctl.guard.Baseline = func(s string) bool { return s == self || base != nil && base(s) }
	}
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	if err := ctl.load(ctx); err != nil {
		return nil, err
	}
	resp, err := c.Get(ctx, fleet.DisabledAll, clientv3.WithPrefix(), clientv3.WithKeysOnly())
	if err != nil {
		return nil, err
	}
	for _, kv := range resp.Kvs {
		ctl.disabled[strings.TrimPrefix(string(kv.Key), fleet.DisabledAll)] = true
	}
	return ctl, nil
}

func selfHash() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// floor is the highest version published from this directory, kept
// beside etcd's data so that losing it does not start the versions over.
func (ctl *Controller) floor() uint64 {
	b, err := os.ReadFile(filepath.Join(ctl.dir, "rules.version"))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (ctl *Controller) setFloor(v uint64) error {
	path := filepath.Join(ctl.dir, "rules.version")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// load reads the published set. A set older than the floor goes on from
// the floor: agents refuse any version below one they hold.
func (ctl *Controller) load(ctx context.Context) error {
	if err := ctl.read(ctx); err != nil {
		return err
	}
	if f := ctl.floor(); f > ctl.set.Version {
		ctl.record(incident.Incident{Kind: "rules-reset", Action: "alert", Severity: model.SevCritical,
			Detail: fmt.Sprintf("etcd holds version %d but %d was published: continuing from %d; rules since are lost", ctl.set.Version, f, f)})
		ctl.set.Version = f
	}
	return nil
}

func (ctl *Controller) read(ctx context.Context) error {
	resp, err := ctl.c.Get(ctx, fleet.RulesKey)
	if err != nil {
		return err
	}
	if len(resp.Kvs) == 0 {
		ctl.set, ctl.rev = &rules.Set{}, 0
		return nil
	}
	e, err := rules.Unmarshal(resp.Kvs[0].Value)
	if err != nil {
		return err
	}
	s, err := rules.Open(e, ctl.key.Public().(ed25519.PublicKey))
	if err != nil {
		return fmt.Errorf("published rule set: %w", err)
	}
	ctl.set, ctl.rev = s, resp.Kvs[0].ModRevision
	return nil
}

// Current is a copy of the rule set in force.
func (ctl *Controller) Current() *rules.Set {
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	s := *ctl.set
	s.Rules = slices.Clone(s.Rules)
	return &s
}

// errNoChange means change left the set as it was.
var errNoChange = errors.New("no change")

// write publishes the next version: change edits a copy of the set in
// force. If another writer published first, the set is read again and
// change applied to that.
func (ctl *Controller) write(ctx context.Context, change func(*rules.Set) error) (*rules.Set, error) {
	ctl.mu.Lock()
	defer ctl.mu.Unlock()
	for range writeTries {
		next := *ctl.set
		next.Rules = slices.Clone(next.Rules)
		if err := change(&next); err != nil {
			return nil, err
		}
		next.Version++
		next.Issued = ctl.now().UTC()
		e, err := rules.Sign(&next, ctl.key)
		if err != nil {
			return nil, err
		}
		b, err := rules.Marshal(e)
		if err != nil {
			return nil, err
		}
		if len(b) > ctl.maxSet {
			return nil, fmt.Errorf("fleet size (%d bytes)", ctl.maxSet)
		}
		resp, err := ctl.c.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(fleet.RulesKey), "=", ctl.rev)).
			Then(clientv3.OpPut(fleet.RulesKey, string(b))).
			Commit()
		if err != nil {
			return nil, err
		}
		if resp.Succeeded {
			ctl.set, ctl.rev = &next, resp.Header.Revision
			if err := ctl.setFloor(next.Version); err != nil {
				ctl.record(incident.Incident{Kind: "rules-reset", Action: "alert", Severity: model.SevHigh, Detail: "version floor: " + err.Error()})
			}
			return &next, nil
		}
		if err := ctl.load(ctx); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("rule set: another writer keeps winning")
}

// Revoke publishes the next version without rule id, and keeps id from
// being promoted again.
func (ctl *Controller) Revoke(ctx context.Context, id string) error {
	_, err := ctl.write(ctx, func(s *rules.Set) error {
		i := slices.IndexFunc(s.Rules, func(r rules.Rule) bool { return r.ID == id })
		if i < 0 {
			return fmt.Errorf("no rule %s", id)
		}
		s.Rules = slices.Delete(s.Rules, i, i+1)
		return nil
	})
	if err != nil {
		return err
	}
	_, err = ctl.c.Put(ctx, fleet.RevokedAll+id, ctl.now().UTC().Format(time.RFC3339))
	return err
}

// DisableHost takes away host's write access, for good: its agent keeps
// the rule set but can no longer propose, report or send heartbeats.
func (ctl *Controller) DisableHost(ctx context.Context, host, why string) error {
	if _, err := ctl.c.Put(ctx, fleet.DisabledAll+host, why); err != nil {
		return err
	}
	if err := revokeWrites(ctx, ctl.c, host); err != nil {
		return err
	}
	ctl.mu.Lock()
	ctl.disabled[host] = true
	ctl.mu.Unlock()
	ctl.record(incident.Incident{Kind: "host-disabled", Action: "alert", Severity: model.SevCritical, Host: host, Detail: why})
	return nil
}

// flooded counts one write by host and reports whether it is past the
// limit for the first time in this window.
func (ctl *Controller) flooded(host string) bool {
	now := ctl.now()
	if now.Sub(ctl.windowAt) >= floodWindow {
		clear(ctl.writes)
		ctl.windowAt = now
	}
	ctl.writes[host]++
	return ctl.writes[host] == ctl.floodLimit+1
}

func (ctl *Controller) record(in incident.Incident) {
	if ctl.log == nil {
		return
	}
	if in.Time.IsZero() {
		in.Time = ctl.now()
	}
	ctl.log.Add(in)
}

// about is an incident naming rule r.
func about(kind string, sev model.Severity, host string, r rules.Rule, detail string) incident.Incident {
	in := incident.Incident{Kind: kind, Action: "alert", Severity: sev, Host: host, Exe: r.Exe, SHA256: r.SHA256, Detail: detail}
	if r.Kind == "remote" && r.Addr.IsValid() {
		in.Remote = &incident.Endpoint{Addr: r.Addr.String(), Port: r.Port, Proto: r.Proto}
	}
	return in
}

// propose judges one proposal. Whatever the outcome, the caller deletes it.
func (ctl *Controller) propose(ctx context.Context, host, id string, val []byte) {
	reject := func(r rules.Rule, why string) {
		ctl.record(about("rule-rejected", model.SevMedium, host, r, "rule "+id+": "+why))
	}
	if len(val) > maxValue {
		reject(rules.Rule{}, fmt.Sprintf("%d bytes", len(val)))
		return
	}
	var r rules.Rule
	if err := json.Unmarshal(val, &r); err != nil {
		reject(rules.Rule{}, "not a rule: "+err.Error())
		return
	}
	r.From = host
	r.SetID()
	if r.ID != id {
		reject(r, "id does not match the rule")
		return
	}
	if err := r.Bound(ctl.now().UTC()); err != nil {
		reject(r, err.Error())
		return
	}
	if err := ctl.guard.Validate(r); err != nil {
		reject(r, err.Error())
		return
	}
	if resp, err := ctl.c.Get(ctx, fleet.RevokedAll+r.ID, clientv3.WithKeysOnly()); err != nil {
		reject(r, err.Error())
		return
	} else if len(resp.Kvs) > 0 {
		reject(r, "revoked")
		return
	}
	s, err := ctl.write(ctx, func(s *rules.Set) error {
		mine := 0
		for _, have := range s.Rules {
			if have.Key() == r.Key() {
				return errNoChange
			}
			if have.From == host {
				mine++
			}
		}
		switch {
		case mine >= ctl.hostCap:
			return fmt.Errorf("host limit (%d rules)", ctl.hostCap)
		case len(s.Rules) >= ctl.totalCap:
			return fmt.Errorf("fleet limit (%d rules)", ctl.totalCap)
		}
		s.Rules = append(s.Rules, r)
		return nil
	})
	switch {
	case errors.Is(err, errNoChange):
	case err != nil:
		reject(r, err.Error())
	default:
		ctl.record(about("rule-promoted", model.SevHigh, host, r, fmt.Sprintf("rule %s %s promoted, version %d", r.ID, r.Key(), s.Version)))
	}
}

// ingest logs one of host's incidents.
func (ctl *Controller) ingest(host string, val []byte) {
	var in incident.Incident
	if len(val) > maxValue {
		in = incident.Incident{Kind: "incident-dropped", Action: "alert", Severity: model.SevMedium, Detail: fmt.Sprintf("%d bytes", len(val))}
	} else if err := json.Unmarshal(val, &in); err != nil {
		in = incident.Incident{Kind: "incident-dropped", Action: "alert", Severity: model.SevMedium, Detail: err.Error()}
	}
	in.Host = host
	ctl.record(in)
}

func (ctl *Controller) heartbeat(host string, put bool) {
	b := ctl.beats[host]
	if b == nil {
		b = &beat{}
		ctl.beats[host] = b
	}
	switch {
	case put:
		b.seen = true
		if b.silent {
			b.silent = false
			ctl.record(incident.Incident{Kind: "agent-back", Action: "alert", Severity: model.SevMedium, Host: host, Detail: "heartbeat again"})
		}
	case !b.silent:
		b.silent = true
		ctl.record(incident.Incident{Kind: "agent-silent", Action: "alert", Severity: model.SevHigh, Host: host, Detail: "heartbeat lease expired"})
	}
}

// addUsers gives hosts enrolled since the last look their etcd user, so
// enrolling needs no restart.
func (ctl *Controller) addUsers(ctx context.Context) {
	hosts, err := pki.Hosts(ctl.dir)
	if err != nil {
		return
	}
	var add []string
	for _, h := range hosts {
		if !ctl.users[h] {
			add = append(add, h)
		}
	}
	if len(add) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if err := Bootstrap(ctx, ctl.c, add); err != nil {
		return // tried again next tick
	}
	for _, h := range add {
		ctl.users[h] = true
	}
}

// checkSilent reports enrolled hosts that have not sent a heartbeat since
// the controller started.
func (ctl *Controller) checkSilent() {
	if ctl.now().Sub(ctl.started) < ctl.silentAfter {
		return
	}
	hosts, err := pki.Hosts(ctl.dir)
	if err != nil {
		return
	}
	for _, h := range hosts {
		b := ctl.beats[h]
		if b == nil {
			b = &beat{}
			ctl.beats[h] = b
		}
		if !b.seen && !b.silent {
			b.silent = true
			ctl.record(incident.Incident{Kind: "agent-silent", Action: "alert", Severity: model.SevHigh, Host: h,
				Detail: fmt.Sprintf("no heartbeat in %s since the controller started", ctl.silentAfter)})
		}
	}
}

// change is one key put or deleted under a watched prefix.
type change struct {
	prefix string
	key    string
	val    []byte
	del    bool
}

// follow sends every key under prefix, then every change to it, to out.
// After a watch ends it starts over with a fresh read.
func (ctl *Controller) follow(ctx context.Context, prefix string, out chan<- change) {
	send := func(c change) bool {
		select {
		case out <- c:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for ctx.Err() == nil {
		gctx, cancel := context.WithTimeout(ctx, opTimeout)
		resp, err := ctl.c.Get(gctx, prefix, clientv3.WithPrefix())
		cancel()
		if err != nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
			}
			continue
		}
		for _, kv := range resp.Kvs {
			if !send(change{prefix, string(kv.Key), kv.Value, false}) {
				return
			}
		}
		w := ctl.c.Watch(clientv3.WithRequireLeader(ctx), prefix, clientv3.WithPrefix(), clientv3.WithRev(resp.Header.Revision+1))
		for wr := range w {
			if wr.Err() != nil {
				break
			}
			for _, ev := range wr.Events {
				if !send(change{prefix, string(ev.Kv.Key), ev.Kv.Value, ev.Type == clientv3.EventTypeDelete}) {
					return
				}
			}
		}
	}
}

func (ctl *Controller) handle(ctx context.Context, ch change) {
	host, rest, ok := fleet.HostOf(ch.key, ch.prefix)
	if !ok {
		return
	}
	if !ch.del {
		ctl.mu.Lock()
		off := ctl.disabled[host]
		ctl.mu.Unlock()
		switch {
		case off:
			if ch.prefix != fleet.HeartbeatAll {
				ctl.delete(ctx, ch.key)
			}
			return
		case ctl.flooded(host):
			why := fmt.Sprintf("more than %d writes in %s", ctl.floodLimit, floodWindow)
			if err := ctl.DisableHost(ctx, host, why); err != nil {
				ctl.record(incident.Incident{Kind: "host-disabled", Action: "alert", Severity: model.SevCritical, Host: host, Detail: why + ": not disabled: " + err.Error()})
			}
			ctl.delete(ctx, ch.key)
			return
		}
	}
	switch ch.prefix {
	case fleet.ProposedAll:
		if ch.del {
			return
		}
		ctl.propose(ctx, host, rest, ch.val)
		ctl.delete(ctx, ch.key)
	case fleet.IncidentsAll:
		if ch.del {
			return
		}
		ctl.ingest(host, ch.val)
		ctl.delete(ctx, ch.key)
	case fleet.HeartbeatAll:
		if rest == "" {
			ctl.heartbeat(host, !ch.del)
		}
	}
}

func (ctl *Controller) delete(ctx context.Context, key string) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	ctl.c.Delete(ctx, key)
}

// Run follows proposals, incidents and heartbeats until ctx is done.
func (ctl *Controller) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctl.started = ctl.now()
	changes := make(chan change, 256)
	var wg sync.WaitGroup
	for _, p := range []string{fleet.ProposedAll, fleet.IncidentsAll, fleet.HeartbeatAll} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctl.follow(ctx, p, changes)
		}()
	}
	defer wg.Wait()
	tick := time.NewTicker(ctl.tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ch := <-changes:
			ctl.handle(ctx, ch)
		case <-tick.C:
			ctl.addUsers(ctx)
			ctl.checkSilent()
		}
	}
}
