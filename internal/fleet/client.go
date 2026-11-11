package fleet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/collect"
	"xdr/internal/config"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

const (
	queueLen   = 256
	opTimeout  = 5 * time.Second
	maxCache   = 8 << 20
	leaseTTL   = 10 // seconds
	beatEvery  = 3 * time.Second
	downAfter  = 10 * time.Second
	maxBackoff = 30 * time.Second
)

// item is one key the client is to put.
type item struct {
	key string
	val []byte
}

// Client is an agent's link to the controller: it keeps the verified rule
// set current and on disk, and sends proposals, incidents and heartbeats.
// Nothing it does ever waits on etcd in the caller's goroutine.
type Client struct {
	host  string
	f     config.Fleet
	cache string
	pub   ed25519.PublicKey

	ttl                         int64
	beatEvery, unreachableAfter time.Duration
	maxBackoff                  time.Duration

	queue   chan item
	seq     atomic.Uint64
	mu      sync.Mutex
	version uint64 // the highest version accepted
}

// New is a client for host. cachePath is where the last verified set is
// kept; pub is the controller's rule-signing key.
func New(host string, f config.Fleet, cachePath string, pub ed25519.PublicKey) *Client {
	return &Client{
		host: host, f: f, cache: cachePath, pub: pub,
		ttl: leaseTTL, beatEvery: beatEvery, unreachableAfter: downAfter, maxBackoff: maxBackoff,
		queue: make(chan item, queueLen),
	}
}

// Cached is the set in the cache file, verified; nil when there is none.
func (c *Client) Cached() (*rules.Set, error) {
	b, err := collect.ReadFile(c.cache, maxCache)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e, err := rules.Unmarshal(b)
	if err != nil {
		return nil, err
	}
	s, err := rules.Open(e, c.pub)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.cache, err)
	}
	c.mu.Lock()
	c.version = max(c.version, s.Version)
	c.mu.Unlock()
	return s, nil
}

// enqueue adds it, dropping the oldest item when the queue is full.
func (c *Client) enqueue(it item) {
	for {
		select {
		case c.queue <- it:
			return
		default:
		}
		select {
		case <-c.queue:
		default:
		}
	}
}

// Propose sends rules for the controller to judge.
func (c *Client) Propose(rs []rules.Rule) {
	for _, r := range rs {
		b, err := json.Marshal(r)
		if err == nil {
			c.enqueue(item{Proposed(c.host) + r.ID, b})
		}
	}
}

// Report sends an incident line to the controller.
func (c *Client) Report(in incident.Incident) {
	b, err := json.Marshal(in)
	if err != nil {
		return
	}
	key := Incidents(c.host) + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(c.seq.Add(1), 10)
	c.enqueue(item{key, b})
}

// writeCache stores b atomically, readable by root only.
func (c *Client) writeCache(b []byte) error {
	if err := os.MkdirAll(filepath.Dir(c.cache), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(c.cache), ".rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.cache)
}

// apply verifies a stored envelope and, if it is newer, caches it and
// hands it on.
func (c *Client) apply(b []byte, onRules func(*rules.Set), onIncident func(incident.Incident)) {
	refuse := func(why string) {
		onIncident(incident.Incident{Time: time.Now(), Kind: "rules-refused", Action: "alert", Severity: model.SevCritical, Detail: why})
	}
	e, err := rules.Unmarshal(b)
	if err != nil {
		refuse(err.Error())
		return
	}
	s, err := rules.Open(e, c.pub)
	if err != nil {
		refuse(err.Error())
		return
	}
	c.mu.Lock()
	have := c.version
	c.mu.Unlock()
	switch {
	case s.Version == have:
		return
	case s.Version < have:
		refuse(fmt.Sprintf("version %d is older than %d, in force", s.Version, have))
		return
	}
	if err := c.writeCache(b); err != nil {
		onIncident(incident.Incident{Time: time.Now(), Kind: "fleet", Action: "alert", Severity: model.SevHigh, Detail: "rule cache: " + err.Error()})
	}
	c.mu.Lock()
	c.version = s.Version
	c.mu.Unlock()
	onRules(s)
}

func (c *Client) dial() (*clientv3.Client, error) {
	tc, err := pki.ClientTLS(filepath.Join(c.f.Dir, "ca.pem"), filepath.Join(c.f.Dir, "host.pem"), filepath.Join(c.f.Dir, "host-key.pem"))
	if err != nil {
		return nil, err
	}
	return clientv3.New(clientv3.Config{Endpoints: c.f.Endpoints, TLS: tc, DialTimeout: opTimeout})
}

func (c *Client) beat(ctx context.Context, cli *clientv3.Client, lease clientv3.LeaseID) error {
	c.mu.Lock()
	v := c.version
	c.mu.Unlock()
	b, _ := json.Marshal(struct {
		Time    time.Time `json:"time"`
		Version uint64    `json:"version"`
	}{time.Now().UTC(), v})
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	_, err := cli.Put(ctx, Heartbeat(c.host), string(b), clientv3.WithLease(lease))
	return err
}

// session is one connection: it returns when the connection fails or ctx
// is done. up is called once etcd has answered.
func (c *Client) session(ctx context.Context, cli *clientv3.Client, up func(), onRules func(*rules.Set), onIncident func(incident.Incident)) error {
	gctx, cancel := context.WithTimeout(ctx, opTimeout)
	resp, err := cli.Get(gctx, RulesKey)
	cancel()
	if err != nil {
		return err
	}
	up()
	if len(resp.Kvs) == 1 {
		c.apply(resp.Kvs[0].Value, onRules, onIncident)
	}
	gctx, cancel = context.WithTimeout(ctx, opTimeout)
	lease, err := cli.Grant(gctx, c.ttl)
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cli.Revoke(rctx, lease.ID)
	}()
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	alive, err := cli.KeepAlive(sctx, lease.ID)
	if err != nil {
		return err
	}
	if err := c.beat(ctx, cli, lease.ID); err != nil {
		return err
	}
	watch := cli.Watch(clientv3.WithRequireLeader(sctx), RulesKey, clientv3.WithRev(resp.Header.Revision+1))
	beats := time.NewTicker(c.beatEvery)
	defer beats.Stop()
	var pending *item
	for {
		if pending != nil {
			pctx, cancel := context.WithTimeout(ctx, opTimeout)
			_, err := cli.Put(pctx, pending.key, string(pending.val))
			cancel()
			if err != nil {
				c.enqueue(*pending)
				return err
			}
			pending = nil
		}
		select {
		case <-ctx.Done():
			return nil
		case it := <-c.queue:
			pending = &it
		case wr, ok := <-watch:
			if !ok || wr.Err() != nil {
				return errors.New("rule watch ended")
			}
			for _, ev := range wr.Events {
				if ev.Type == clientv3.EventTypePut {
					c.apply(ev.Kv.Value, onRules, onIncident)
				}
			}
		case _, ok := <-alive:
			if !ok {
				return errors.New("heartbeat lease lost")
			}
		case <-beats.C:
			if err := c.beat(ctx, cli, lease.ID); err != nil {
				return err
			}
		}
	}
}

// Run keeps the client connected until ctx is done. New verified sets go
// to onRules; the client's own incidents (refused sets, losing and
// regaining etcd) go to onIncident. Both may be called from any of Run's
// goroutines, one call at a time.
func (c *Client) Run(ctx context.Context, onRules func(*rules.Set), onIncident func(incident.Incident)) {
	var mu sync.Mutex // one callback at a time; guards the state below
	// A session is healthy once it has lasted unreachableAfter: one that
	// answers and then fails, again and again, is as good as none.
	up, healthy, reported, downSince := false, false, false, time.Now()
	var upAt time.Time
	var lastErr error
	alert := func(detail string) {
		onIncident(incident.Incident{Time: time.Now(), Kind: "fleet", Action: "alert", Severity: model.SevHigh, Detail: detail})
	}
	locked := func(fn func()) { mu.Lock(); defer mu.Unlock(); fn() }
	safeRules := func(s *rules.Set) { locked(func() { onRules(s) }) }
	safeIncident := func(in incident.Incident) { locked(func() { onIncident(in) }) }

	// The watchdog says so once when etcd has been out of reach too long,
	// whatever the dialer is waiting on.
	var wg sync.WaitGroup
	defer wg.Wait()
	wctx, stop := context.WithCancel(ctx)
	defer stop()
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(max(c.unreachableAfter/10, 10*time.Millisecond))
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
			}
			locked(func() {
				switch {
				case up && !healthy && time.Since(upAt) >= c.unreachableAfter:
					healthy = true
					if reported {
						reported = false
						alert("etcd reconnected")
					}
				case !up && !healthy && !reported && time.Since(downSince) >= c.unreachableAfter:
					reported = true
					alert(fmt.Sprintf("etcd unreachable for %s: %v", c.unreachableAfter, lastErr))
				}
			})
		}
	}()

	backoff := time.Second
	for ctx.Err() == nil {
		cli, err := c.dial()
		if err == nil {
			err = c.session(ctx, cli, func() {
				locked(func() { up, upAt = true, time.Now() })
			}, safeRules, safeIncident)
			cli.Close()
		}
		if ctx.Err() != nil {
			return
		}
		wasHealthy := false
		locked(func() {
			wasHealthy = healthy
			if healthy {
				healthy, downSince = false, time.Now()
			}
			up, lastErr = false, err
		})
		if wasHealthy {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(backoff, c.maxBackoff)):
		}
		backoff = min(backoff*2, c.maxBackoff)
	}
}
