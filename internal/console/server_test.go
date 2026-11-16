package console

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xdr/internal/pki"
)

const goodPassword = "correct horse battery"

type serverRig struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	log  *bytes.Buffer
	now  *clock
	dir  string
	acts *Actions
}

func newServerRig(t *testing.T) *serverRig {
	t.Helper()
	dir := t.TempDir()
	if err := SetPassword(dir, goodPassword); err != nil {
		t.Fatal(err)
	}
	c := &clock{t0}
	s, err := NewState(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	logbuf := &bytes.Buffer{}
	srv := NewServer(dir, func() View { return s.View(nil, nil) }, &Actions{Dir: dir, State: s, Now: c.now}, c.now, logbuf)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &serverRig{t: t, srv: srv, ts: ts, log: logbuf, now: c, dir: dir}
}

func (r *serverRig) do(method, path, cookie string, body any, headers map[string]string) *http.Response {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.ts.URL+path, rd)
	if cookie != "" {
		req.Header.Set("Cookie", "xdr="+cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (r *serverRig) login(password string) (*http.Response, string) {
	resp := r.do("POST", "/login", "", map[string]string{"password": password}, nil)
	for _, c := range resp.Cookies() {
		if c.Name == "xdr" {
			return resp, c.Value
		}
	}
	return resp, ""
}

func TestAPI_RequiresSession(t *testing.T) {
	r := newServerRig(t)
	routes := []struct{ method, path string }{{"GET", "/api/state"}, {"POST", "/api/decide"}, {"GET", "/api/creds"}, {"POST", "/api/rotate"}, {"POST", "/api/breakglass"}}
	for _, rt := range routes {
		if resp := r.do(rt.method, rt.path, "", map[string]string{}, map[string]string{"X-XDR": "1"}); resp.StatusCode != 401 {
			t.Errorf("%s %s without a cookie: %d", rt.method, rt.path, resp.StatusCode)
		}
		if resp := r.do(rt.method, rt.path, "deadbeef", map[string]string{}, map[string]string{"X-XDR": "1"}); resp.StatusCode != 401 {
			t.Errorf("%s %s with a bad cookie: %d", rt.method, rt.path, resp.StatusCode)
		}
	}
}

func TestAuth_LoginLogout(t *testing.T) {
	r := newServerRig(t)
	resp, tok := r.login(goodPassword)
	if resp.StatusCode != 204 || len(tok) != 64 {
		t.Fatalf("login: %d, cookie %q", resp.StatusCode, tok)
	}
	var c *http.Cookie
	for _, k := range resp.Cookies() {
		c = k
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.MaxAge != 43200 || c.Path != "/" {
		t.Fatalf("cookie attributes: %+v", c)
	}
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 200 {
		t.Fatalf("state with the cookie: %d", got.StatusCode)
	}
	r.do("POST", "/logout", tok, nil, map[string]string{"X-XDR": "1"})
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 401 {
		t.Fatalf("state after logout: %d", got.StatusCode)
	}
	_, tok = r.login(goodPassword)
	r.now.t = t0.Add(12*time.Hour + time.Second)
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 401 {
		t.Fatalf("state after 12 h: %d", got.StatusCode)
	}
	if resp, _ := r.login("wrong password entirely"); resp.StatusCode != 401 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
}

func TestAuth_RateLimited(t *testing.T) {
	r := newServerRig(t)
	for i := 1; i <= 5; i++ {
		if resp, _ := r.login("wrong " + strings.Repeat("x", i)); resp.StatusCode != 401 {
			t.Fatalf("failure %d: %d", i, resp.StatusCode)
		}
	}
	if resp, tok := r.login("wrong again"); resp.StatusCode != 429 || tok != "" {
		t.Fatalf("the 6th: %d", resp.StatusCode)
	}
	if resp, tok := r.login(goodPassword); resp.StatusCode != 429 || tok != "" {
		t.Fatalf("a right password while blocked: %d", resp.StatusCode)
	}
	r.now.t = t0.Add(61 * time.Second)
	if resp, tok := r.login(goodPassword); resp.StatusCode != 204 || tok == "" {
		t.Fatalf("after the window: %d", resp.StatusCode)
	}
}

func TestAuth_GlobalRateLimit(t *testing.T) {
	r := newServerRig(t)
	for i := 0; i < 20; i++ {
		r.srv.fail("198.51.100." + string(rune('a'+i%26)) + strings.Repeat("1", i/26)) // many sources
	}
	if resp, _ := r.login(goodPassword); resp.StatusCode != 429 {
		t.Fatalf("after 20 failures from many sources: %d", resp.StatusCode)
	}
}

func TestAuth_CSRF(t *testing.T) {
	r := newServerRig(t)
	_, tok := r.login(goodPassword)
	resp := r.do("POST", "/api/decide", tok, map[string]string{"id": "s:web01:7", "action": "approve"}, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("a POST without X-XDR: %d", resp.StatusCode)
	}
	resp = r.do("POST", "/api/decide", tok, map[string]string{"id": "s:web01:7", "action": "approve"}, map[string]string{"X-XDR": "1"})
	if resp.StatusCode == 403 || resp.StatusCode == 401 {
		t.Fatalf("a POST with X-XDR and the cookie: %d", resp.StatusCode)
	}
}

func TestHeaders_CSP(t *testing.T) {
	r := newServerRig(t)
	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "no-referrer",
	}
	for _, path := range []string{"/", "/app.js", "/api/state", "/nope", "/login"} {
		resp := r.do("GET", path, "", nil, nil)
		for h, v := range want {
			if got := resp.Header.Get(h); got != v {
				t.Errorf("%s %s: %q, want %q", path, h, got, v)
			}
		}
	}
}

func TestAuth_PasswordNeverLogged(t *testing.T) {
	r := newServerRig(t)
	r.login("a wrong password with secrets")
	_, tok := r.login(goodPassword)
	r.do("GET", "/api/state", tok, nil, nil)
	for _, secret := range []string{goodPassword, "a wrong password with secrets", tok} {
		if strings.Contains(r.log.String(), secret) {
			t.Fatalf("the log holds a secret:\n%s", r.log.String())
		}
	}
}

func TestPassword_HashAndCheck(t *testing.T) {
	dir := t.TempDir()
	if err := SetPassword(dir, "short"); err == nil {
		t.Fatal("a short password was accepted")
	}
	if err := SetPassword(dir, goodPassword); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "console.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("console.json: %v %v", st, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "console.json"))
	if !strings.Contains(string(b), `$6$rounds=100000$`) || strings.Contains(string(b), goodPassword) {
		t.Fatalf("console.json: %s", b)
	}
	if !CheckPassword(dir, goodPassword) || CheckPassword(dir, goodPassword+"x") || CheckPassword(t.TempDir(), goodPassword) {
		t.Fatal("CheckPassword")
	}
}

func TestServe_TLS13Only(t *testing.T) {
	dir := t.TempDir()
	if err := pki.Init(dir, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := SetPassword(dir, goodPassword); err != nil {
		t.Fatal(err)
	}
	c := &clock{t0}
	s, _ := NewState(dir, c.now)
	srv := NewServer(dir, func() View { return s.View(nil, nil) }, &Actions{Dir: dir, State: s, Now: c.now}, c.now, io.Discard)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, dir, srv) }()
	t.Cleanup(func() { cancel(); <-done })
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	dial := func(max uint16) error {
		conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MaxVersion: max})
		if err == nil {
			conn.Close()
		}
		return err
	}
	if err := dial(tls.VersionTLS13); err != nil {
		t.Fatalf("TLS 1.3: %v", err)
	}
	if err := dial(tls.VersionTLS12); err == nil {
		t.Fatal("TLS 1.2 was accepted")
	}
}

// The limit is on attempts, counted before the (slow) password check: a
// burst of parallel guesses must not all get checked.
func TestAuth_ParallelGuessesAreCounted(t *testing.T) {
	r := newServerRig(t)
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, _ := r.login("guess number " + strings.Repeat("x", i+1))
			mu.Lock()
			codes[resp.StatusCode]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[401] > failPerSource {
		t.Fatalf("%d wrong passwords were checked in one burst, limit %d: %v", codes[401], failPerSource, codes)
	}
	if codes[429] < 40-failPerSource {
		t.Fatalf("the rest should be refused unchecked: %v", codes)
	}
}

// A right password does not use up an attempt.
func TestAuth_SuccessReleasesItsAttempt(t *testing.T) {
	r := newServerRig(t)
	for i := 0; i < failPerSource-1; i++ {
		r.login("wrong password " + strings.Repeat("y", i+1))
	}
	if resp, tok := r.login(goodPassword); resp.StatusCode != 204 || tok == "" {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	if resp, _ := r.login("one more wrong password"); resp.StatusCode != 401 {
		t.Fatalf("the successful login used an attempt: %d", resp.StatusCode)
	}
}

// Logout is a write: a cross-site form must not be able to log the
// operator out.
func TestAuth_LogoutNeedsHeader(t *testing.T) {
	r := newServerRig(t)
	_, tok := r.login(goodPassword)
	if got := r.do("POST", "/logout", tok, nil, nil); got.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without the header: %d", got.StatusCode)
	}
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 200 {
		t.Fatalf("session gone after a refused logout: %d", got.StatusCode)
	}
}

// A new password ends every session made with the old one.
func TestAuth_PasswordChangeEndsSessions(t *testing.T) {
	r := newServerRig(t)
	_, tok := r.login(goodPassword)
	if err := SetPassword(r.dir, "another long passphrase"); err != nil {
		t.Fatal(err)
	}
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 401 {
		t.Fatalf("old session after a password change: %d", got.StatusCode)
	}
	_, tok = r.login("another long passphrase")
	if got := r.do("GET", "/api/state", tok, nil, nil); got.StatusCode != 200 {
		t.Fatalf("new session: %d", got.StatusCode)
	}
}
