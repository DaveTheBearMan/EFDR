package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"
)

//go:embed web/index.html web/app.js web/app.css
var webFS embed.FS

const (
	cookieName       = "xdr"
	sessionLife      = 12 * time.Hour
	maxLoginSessions = 100
	failWindow       = time.Minute
	failPerSource    = 5
	failTotal        = 20
	maxBody          = 64 << 10
	maxFailKeys      = 10000
)

// csp lets the page run only its own script and style: nothing inline, so
// text from an agent can never become code.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Server is the console's HTTP side: the page, the login and the API.
type Server struct {
	dir  string
	view func() View
	act  *Actions
	now  func() time.Time
	log  *log.Logger

	checks   chan struct{} // two password checks at a time: each costs 100000 rounds of sha512
	mu       sync.Mutex
	sessions map[[32]byte]time.Time // sha256 of the cookie → expiry
	fails    map[string][]time.Time
	allFails []time.Time
}

// NewServer is a server over view and act; dir holds console.json. Its
// log (no passwords, no cookies) goes to logw.
func NewServer(dir string, view func() View, act *Actions, now func() time.Time, logw io.Writer) *Server {
	return &Server{dir: dir, view: view, act: act, now: now, log: log.New(logw, "console: ", log.LstdFlags),
		sessions: map[[32]byte]time.Time{}, fails: map[string][]time.Time{}, checks: make(chan struct{}, 2)}
}

// Serve serves srv over TLS 1.3 on l with dir's server certificate, until
// ctx is done.
func Serve(ctx context.Context, l net.Listener, dir string, srv *Server) error {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"))
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          srv.log,
	}
	go func() { <-ctx.Done(); hs.Close() }()
	if err := hs.Serve(tls.NewListener(l, hs.TLSConfig)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Handler is the routes, with the security headers on every response.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static := func(name, ctype string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := webFS.ReadFile("web/" + name)
			w.Header().Set("Content-Type", ctype)
			w.Write(b)
		}
	}
	mux.HandleFunc("GET /{$}", static("index.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /app.js", static("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /app.css", static("app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /api/state", s.api(false, s.state))
	mux.HandleFunc("POST /api/decide", s.api(true, s.decide))
	mux.HandleFunc("GET /api/creds", s.api(false, s.credsList))
	mux.HandleFunc("POST /api/rotate", s.api(true, s.rotate))
	mux.HandleFunc("POST /api/breakglass", s.api(true, s.breakglass))
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func source(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) prune(now time.Time) {
	keep := func(ts []time.Time) []time.Time {
		i := 0
		for i < len(ts) && now.Sub(ts[i]) >= failWindow {
			i++
		}
		return ts[i:]
	}
	s.allFails = keep(s.allFails)
	for ip, ts := range s.fails {
		if ts = keep(ts); len(ts) == 0 {
			delete(s.fails, ip)
		} else {
			s.fails[ip] = ts
		}
	}
}

// reserve counts a login attempt from ip before it is checked, and says
// no when this source, or all sources together, have used up the minute's
// attempts. Counting first is what holds against a burst of parallel
// guesses; a right password gives its attempt back (release).
func (s *Server) reserve(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.prune(now)
	if len(s.fails[ip]) >= failPerSource || len(s.allFails) >= failTotal {
		return false
	}
	if len(s.fails) >= maxFailKeys {
		s.fails = map[string][]time.Time{}
	}
	s.fails[ip] = append(s.fails[ip], now)
	s.allFails = append(s.allFails, now)
	return true
}

// release takes back the most recent attempt from ip (it was right).
func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ts := s.fails[ip]; len(ts) > 0 {
		s.fails[ip] = ts[:len(ts)-1]
		if len(s.fails[ip]) == 0 {
			delete(s.fails, ip)
		}
	}
	if n := len(s.allFails); n > 0 {
		s.allFails = s.allFails[:n-1]
	}
}

func (s *Server) fail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.prune(now)
	if len(s.fails) >= maxFailKeys {
		s.fails = map[string][]time.Time{}
	}
	s.fails[ip] = append(s.fails[ip], now)
	s.allFails = append(s.allFails, now)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := source(r)
	if !s.reserve(ip) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}
	var in struct{ Password string }
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	ok := json.NewDecoder(r.Body).Decode(&in) == nil && len(in.Password) <= 1024
	if ok {
		s.checks <- struct{}{}
		ok = CheckPassword(s.dir, in.Password)
		<-s.checks
	}
	if !ok {
		s.log.Printf("login refused from %s", ip)
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	s.release(ip)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "no", http.StatusInternalServerError)
		return
	}
	tok := hex.EncodeToString(raw)
	s.mu.Lock()
	now := s.now()
	for k, exp := range s.sessions {
		if !exp.After(now) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= maxLoginSessions {
		var oldest [32]byte
		var when time.Time
		for k, exp := range s.sessions {
			if when.IsZero() || exp.Before(when) {
				oldest, when = k, exp
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[sha256.Sum256([]byte(tok))] = now.Add(sessionLife)
	s.mu.Unlock()
	s.log.Printf("login from %s", ip)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", MaxAge: int(sessionLife / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(c.Value)))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

// api wraps a handler that needs a live session, and with write also the
// custom header a cross-site form cannot send.
func (s *Server) api(write bool, h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		ok := false
		if err == nil {
			s.mu.Lock()
			exp, found := s.sessions[sha256.Sum256([]byte(c.Value))]
			ok = found && exp.After(s.now())
			s.mu.Unlock()
		}
		if !ok {
			http.Error(w, "log in", http.StatusUnauthorized)
			return
		}
		if write {
			if r.Header.Get("X-XDR") != "1" {
				http.Error(w, "missing header", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail400(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	switch {
	case errors.Is(err, ErrHandled):
		code = http.StatusConflict
	case errors.Is(err, ErrUnknown):
		code = http.StatusNotFound
	}
	http.Error(w, err.Error(), code)
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.view()) }

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Action string }
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.act.Decide(r.Context(), in.ID, in.Action); err != nil {
		fail400(w, err)
		return
	}
	s.log.Printf("decided %s: %s", in.ID, in.Action)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) credsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"entries": s.act.Entries(), "block": s.act.Creds()})
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host         string
		Users, Samba []string
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	out, err := s.act.Rotate(r.Context(), in.Host, in.Users, in.Samba)
	if err != nil {
		fail400(w, err)
		return
	}
	s.log.Printf("rotated %d accounts on %s", len(out), in.Host)
	writeJSON(w, map[string]any{"entries": s.act.Entries()})
}

func (s *Server) breakglass(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Host, Action string
		Minutes      int
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tok, err := s.act.Breakglass(in.Host, in.Action, in.Minutes)
	if err != nil {
		fail400(w, err)
		return
	}
	s.log.Printf("minted a %s token for %s", in.Action, in.Host)
	writeJSON(w, map[string]string{"token": tok})
}
