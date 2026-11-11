// Package mesh is the fleet's backup channel: each agent links to its
// peers over mutual TLS on the XDR port, beats to them, and passes on
// signed rule sets and hunts. A peer is trusted for nothing: a set must
// verify against the rule key, and a hunt only starts a search.
package mesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"xdr/internal/hunt"
	"xdr/internal/incident"
	"xdr/internal/model"
)

const (
	beatEvery   = 3 * time.Second
	silentAfter = 15 * time.Second
	opTimeout   = 5 * time.Second
	maxRules    = 2 << 20
	maxHunt     = 64 << 10
	maxBeat     = 4 << 10
	perSecond   = 20 // requests from one address before 429
	seenHunts   = 1024
	huntQueue   = 64 // hunts waiting to go to one peer
)

// Rules is the agent's verified rule set: Offer takes a newer signed set
// a peer sent, Envelope is the one in force.
type Rules interface {
	Offer([]byte) bool
	Envelope() ([]byte, uint64)
}

// Config is one agent's place in the mesh.
type Config struct {
	Host                 string
	Listen               netip.AddrPort
	Peers                []netip.AddrPort
	ServerTLS, ClientTLS *tls.Config // from pki.PeerTLS
	Rules                Rules
	OnHunt               func(*hunt.Request, netip.Addr) // a new hunt and the peer it came from
	OnIncident           func(incident.Incident)
}

// peer is one configured peer: how to reach it, and when it last beat.
type peer struct {
	addr  netip.AddrPort
	kick  chan struct{} // send it the rule set now
	hunts chan *hunt.Request

	mu     sync.Mutex
	last   time.Time // last inbound beat
	cn     string
	silent bool
}

// Mesh is a running set of peer links.
type Mesh struct {
	cfg                    Config
	beatEvery, silentAfter time.Duration
	peers                  map[netip.Addr]*peer
	client                 *http.Client

	mu      sync.Mutex
	seen    map[string]bool
	order   []string // seen, oldest first
	window  time.Time
	counts  map[netip.Addr]int
	huntsIn atomic.Int64 // hunt posts received, for tests
}

// New is a mesh for cfg; Run starts it.
func New(cfg Config) *Mesh {
	m := &Mesh{cfg: cfg, beatEvery: beatEvery, silentAfter: silentAfter,
		peers: map[netip.Addr]*peer{}, seen: map[string]bool{}, counts: map[netip.Addr]int{}}
	for _, p := range cfg.Peers {
		m.peers[p.Addr().Unmap()] = &peer{addr: p, kick: make(chan struct{}, 1), hunts: make(chan *hunt.Request, huntQueue)}
	}
	dialer := &net.Dialer{Timeout: opTimeout}
	// Dial from the address peers know this box by.
	if a := cfg.Listen.Addr(); a.IsValid() && !a.IsUnspecified() {
		dialer.LocalAddr = &net.TCPAddr{IP: a.AsSlice()}
	}
	m.client = &http.Client{Timeout: opTimeout, Transport: &http.Transport{
		TLSClientConfig: cfg.ClientTLS, DialContext: dialer.DialContext,
		MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: false,
	}}
	return m
}

func (m *Mesh) alert(kind string, sev model.Severity, detail string) {
	if m.cfg.OnIncident != nil {
		m.cfg.OnIncident(incident.Incident{Time: time.Now(), Kind: kind, Action: "alert", Severity: sev, Detail: detail})
	}
}

// remember adds id to the hunts seen and reports whether it is new.
func (m *Mesh) remember(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[id] {
		return false
	}
	m.seen[id] = true
	m.order = append(m.order, id)
	if len(m.order) > seenHunts {
		delete(m.seen, m.order[0])
		m.order = m.order[1:]
	}
	return true
}

// allow counts one request from a and reports whether it is within the
// rate.
func (m *Mesh) allow(a netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if now := time.Now(); now.Sub(m.window) >= time.Second {
		m.window = now
		clear(m.counts)
	}
	m.counts[a]++
	return m.counts[a] <= perSecond
}

// PushRules sends the set in force to every peer now.
func (m *Mesh) PushRules() { m.pushRules(netip.Addr{}) }

func (m *Mesh) pushRules(except netip.Addr) {
	for a, p := range m.peers {
		if a == except {
			continue
		}
		select {
		case p.kick <- struct{}{}:
		default:
		}
	}
}

// PushHunt sends r to every peer but except, and marks it seen so it is
// not taken again when it comes back.
func (m *Mesh) PushHunt(r *hunt.Request, except netip.Addr) {
	m.remember(r.ID)
	m.relay(r, except.Unmap())
}

func (m *Mesh) relay(r *hunt.Request, except netip.Addr) {
	for a, p := range m.peers {
		if a == except {
			continue
		}
		select {
		case p.hunts <- r:
		default:
			m.alert("hunt-dropped", model.SevMedium, fmt.Sprintf("hunt %s: queue to %s full", r.ID, p.addr))
		}
	}
}

// from is the peer address of a request.
func from(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

func cn(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName
}

// read reads a body of at most max bytes, answering 413 past it.
func read(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return nil, false
	case err != nil:
		http.Error(w, "bad body", http.StatusBadRequest)
		return nil, false
	}
	return b, true
}

type beatMsg struct {
	Host    string `json:"host"`
	Version uint64 `json:"version"`
}

func (m *Mesh) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /beat", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := read(w, r, maxBeat); !ok {
			return
		}
		if p := m.peers[from(r)]; p != nil {
			p.mu.Lock()
			back := p.silent
			p.last, p.cn, p.silent = time.Now(), cn(r), false
			p.mu.Unlock()
			if back {
				m.alert("peer-back", model.SevMedium, fmt.Sprintf("peer %s (%s) beats again", p.addr.Addr(), cn(r)))
			}
		}
		_, v := m.cfg.Rules.Envelope()
		json.NewEncoder(w).Encode(beatMsg{Host: m.cfg.Host, Version: v})
	})
	mux.HandleFunc("GET /rules", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := m.cfg.Rules.Envelope()
		if raw == nil {
			http.NotFound(w, r)
			return
		}
		w.Write(raw)
	})
	mux.HandleFunc("POST /rules", func(w http.ResponseWriter, r *http.Request) {
		b, ok := read(w, r, maxRules)
		if !ok {
			return
		}
		if m.cfg.Rules.Offer(b) {
			m.pushRules(from(r))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /hunt", func(w http.ResponseWriter, r *http.Request) {
		m.huntsIn.Add(1)
		b, ok := read(w, r, maxHunt)
		if !ok {
			return
		}
		var h hunt.Request
		if json.Unmarshal(b, &h) != nil || h.Bound() != nil {
			http.Error(w, "bad hunt", http.StatusBadRequest)
			return
		}
		if m.remember(h.ID) {
			if m.cfg.OnHunt != nil {
				m.cfg.OnHunt(&h, from(r))
			}
			m.relay(&h, from(r))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.allow(from(r)) {
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (m *Mesh) url(p *peer, path string) string { return "https://" + p.addr.String() + path }

func (m *Mesh) post(ctx context.Context, p *peer, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url(p, path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return m.client.Do(req)
}

// sendRules posts the set in force to p.
func (m *Mesh) sendRules(ctx context.Context, p *peer) {
	raw, _ := m.cfg.Rules.Envelope()
	if raw == nil {
		return
	}
	if resp, err := m.post(ctx, p, "/rules", raw); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxBeat))
		resp.Body.Close()
	}
}

// beat tells p our version and evens the two sets out.
func (m *Mesh) beat(ctx context.Context, p *peer) {
	_, mine := m.cfg.Rules.Envelope()
	b, _ := json.Marshal(beatMsg{Host: m.cfg.Host, Version: mine})
	resp, err := m.post(ctx, p, "/beat", b)
	if err != nil {
		return
	}
	var got beatMsg
	err = json.NewDecoder(io.LimitReader(resp.Body, maxBeat)).Decode(&got)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	switch {
	case got.Version > mine:
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.url(p, "/rules"), nil)
		if err != nil {
			return
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRules+1))
		resp.Body.Close()
		if err == nil && resp.StatusCode == http.StatusOK && len(raw) <= maxRules && m.cfg.Rules.Offer(raw) {
			m.pushRules(p.addr.Addr().Unmap())
		}
	case got.Version < mine:
		m.sendRules(ctx, p)
	}
}

// link beats p and sends it what is pushed, until ctx is done.
func (m *Mesh) link(ctx context.Context, p *peer) {
	t := time.NewTicker(m.beatEvery)
	defer t.Stop()
	m.beat(ctx, p)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.beat(ctx, p)
		case <-p.kick:
			m.sendRules(ctx, p)
		case h := <-p.hunts:
			b, err := json.Marshal(h)
			if err != nil {
				continue
			}
			if resp, err := m.post(ctx, p, "/hunt", b); err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, maxBeat))
				resp.Body.Close()
			}
		}
	}
}

// watch reports peers that stop beating, once the mesh has run
// silentAfter.
func (m *Mesh) watch(ctx context.Context, start time.Time) {
	t := time.NewTicker(max(m.beatEvery/2, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		if now.Sub(start) < m.silentAfter {
			continue
		}
		for _, p := range m.peers {
			p.mu.Lock()
			last := p.last
			if last.IsZero() {
				last = start
			}
			report := !p.silent && now.Sub(last) >= m.silentAfter
			if report {
				p.silent = true
			}
			name := p.cn
			p.mu.Unlock()
			if report {
				m.alert("peer-silent", model.SevHigh, fmt.Sprintf("peer %s (%s) silent for %s", p.addr.Addr(), name, m.silentAfter))
			}
		}
	}
}

// Run listens for peers and links to each until ctx is done.
func (m *Mesh) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", m.cfg.Listen.String())
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           m.handler(),
		TLSConfig:         m.cfg.ServerTLS,
		ReadHeaderTimeout: opTimeout, ReadTimeout: opTimeout, WriteTimeout: opTimeout, IdleTimeout: time.Minute,
		MaxHeaderBytes: 8 << 10,
		ErrorLog:       log.New(io.Discard, "", 0), // a stranger's failed handshake is not news
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, p := range m.peers {
		wg.Go(func() { m.link(ctx, p) })
	}
	wg.Go(func() { m.watch(ctx, time.Now()) })
	wg.Go(func() {
		<-ctx.Done()
		sctx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		srv.Shutdown(sctx)
	})
	err = srv.ServeTLS(ln, "", "")
	cancel()
	m.client.CloseIdleConnections()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
