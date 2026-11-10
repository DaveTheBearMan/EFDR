package dnsguard

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"xdr/internal/fw"
)

// harness is a Stub serving on a loopback port, with a recording fake
// upstream.
type harness struct {
	t    *testing.T
	addr net.Addr
	stub *Stub

	mu       sync.Mutex
	queries  []Query
	hook     func(Query) // called for each query, when set
	upstream [][]byte
}

func serve(t *testing.T, allowed func(string) bool, answer func(q []byte) ([]byte, error)) *harness {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, addr: pc.LocalAddr()}
	h.stub = &Stub{
		Allowed: allowed,
		Upstream: func(_ context.Context, q []byte) ([]byte, error) {
			h.mu.Lock()
			h.upstream = append(h.upstream, append([]byte(nil), q...))
			h.mu.Unlock()
			return answer(q)
		},
		OnQuery: func(q Query) {
			h.mu.Lock()
			h.queries = append(h.queries, q)
			hook := h.hook
			h.mu.Unlock()
			if hook != nil {
				hook(q)
			}
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.stub.Serve(ctx, pc) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
		pc.Close()
	})
	return h
}

func (h *harness) sent() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]byte(nil), h.upstream...)
}

func (h *harness) seen() []Query {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Query(nil), h.queries...)
}

func query(t *testing.T, id uint16, name string, questions int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	for i := 0; i < questions; i++ {
		if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// answerFor is a response to q carrying one A record.
func answerFor(t *testing.T, q []byte) []byte {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(q); err != nil {
		t.Fatal(err)
	}
	m.Response, m.RecursionAvailable = true, true
	m.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 80}},
	}}
	out, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// ask sends one packet and returns the reply, or nil after wait.
func (h *harness) ask(packet []byte, wait time.Duration) []byte {
	h.t.Helper()
	c, err := net.Dial("udp", h.addr.String())
	if err != nil {
		h.t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(packet); err != nil {
		h.t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func header(t *testing.T, reply []byte) dnsmessage.Header {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		t.Fatalf("reply %x: %v", reply, err)
	}
	return h
}

func none(string) bool { return false }
func all(string) bool  { return true }

func TestStub_BlockedIsNXDOMAIN(t *testing.T) {
	h := serve(t, none, func([]byte) ([]byte, error) { return nil, errors.New("not reached") })
	reply := h.ask(query(t, 0x1234, "evil.example.", 1), time.Second)
	if reply == nil {
		t.Fatal("no reply")
	}
	var m dnsmessage.Message
	if err := m.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	if m.RCode != dnsmessage.RCodeNameError || m.ID != 0x1234 || !m.Response || !m.RecursionDesired || !m.RecursionAvailable {
		t.Fatalf("header %+v", m.Header)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name.String() != "evil.example." || len(m.Answers) != 0 {
		t.Fatalf("message %+v", m)
	}
	seen := h.seen()
	if len(seen) != 1 || seen[0].Name != "evil.example" || seen[0].Allowed || seen[0].Type != uint16(dnsmessage.TypeA) {
		t.Fatalf("queries %+v", seen)
	}
	if !seen[0].Client.Addr().IsLoopback() || seen[0].Client.Port() == 0 {
		t.Fatalf("client %v", seen[0].Client)
	}
	if len(h.sent()) != 0 {
		t.Fatal("blocked name went upstream")
	}
}

func TestStub_AllowedForwarded(t *testing.T) {
	q := query(t, 7, "www.example.com.", 1)
	want := answerFor(t, q)
	h := serve(t, func(n string) bool { return n == "www.example.com" }, func([]byte) ([]byte, error) { return want, nil })
	reply := h.ask(q, time.Second)
	if !bytes.Equal(reply, want) {
		t.Fatalf("reply %x, want %x", reply, want)
	}
	if sent := h.sent(); len(sent) != 1 || !bytes.Equal(sent[0], q) {
		t.Fatalf("upstream got %x", sent)
	}
	if seen := h.seen(); len(seen) != 1 || !seen[0].Allowed {
		t.Fatalf("queries %+v", seen)
	}
}

func TestStub_OnQueryBeforeReply(t *testing.T) {
	h := serve(t, none, nil)
	gate, entered := make(chan struct{}), make(chan struct{})
	h.mu.Lock()
	h.hook = func(Query) { close(entered); <-gate }
	h.mu.Unlock()
	got := make(chan []byte, 1)
	go func() { got <- h.ask(query(t, 1, "evil.example.", 1), 3*time.Second) }()
	<-entered
	select {
	case r := <-got:
		t.Fatalf("reply %x before OnQuery returned", r)
	case <-time.After(300 * time.Millisecond):
	}
	close(gate)
	if r := <-got; r == nil {
		t.Fatal("no reply after OnQuery returned")
	}
}

func TestStub_CaseAndTrailingDot(t *testing.T) {
	var offered []string
	var mu sync.Mutex
	h := serve(t, func(n string) bool {
		mu.Lock()
		offered = append(offered, n)
		mu.Unlock()
		return false
	}, nil)
	h.ask(query(t, 1, "WWW.Example.COM.", 1), time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(offered) != 1 || offered[0] != "www.example.com" {
		t.Fatalf("offered %q", offered)
	}
	if seen := h.seen(); seen[0].Name != "www.example.com" {
		t.Fatalf("query %+v", seen[0])
	}
}

func TestStub_MalformedIgnored(t *testing.T) {
	h := serve(t, none, nil)
	response := query(t, 5, "evil.example.", 1)
	response[2] |= 0x80 // QR
	update := query(t, 6, "evil.example.", 1)
	update[2] |= 5 << 3 // opcode UPDATE
	for name, packet := range map[string][]byte{
		"random":        {0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8},
		"empty":         {},
		"short":         {1, 2, 3},
		"response":      response,
		"update":        update,
		"two questions": query(t, 7, "evil.example.", 2),
		"no question":   query(t, 8, "evil.example.", 0),
		"truncated":     query(t, 9, "evil.example.", 1)[:20],
	} {
		if r := h.ask(packet, 200*time.Millisecond); r != nil {
			t.Errorf("%s: got a reply %x", name, r)
		}
	}
	if seen := h.seen(); len(seen) != 0 {
		t.Fatalf("OnQuery called: %+v", seen)
	}
	if r := h.ask(query(t, 10, "evil.example.", 1), time.Second); r == nil {
		t.Fatal("a good query is no longer answered")
	}
}

func TestStub_UpstreamFailureIsSERVFAIL(t *testing.T) {
	answers := map[string]func(q []byte) ([]byte, error){
		"error":          func([]byte) ([]byte, error) { return nil, errors.New("timeout") },
		"other question": func([]byte) ([]byte, error) { return answerFor(t, query(t, 3, "other.example.", 1)), nil },
		"other id":       func([]byte) ([]byte, error) { return answerFor(t, query(t, 4, "www.example.com.", 1)), nil },
		"not a response": func(q []byte) ([]byte, error) { return q, nil },
		"garbage":        func([]byte) ([]byte, error) { return []byte{1, 2, 3}, nil },
	}
	for name, answer := range answers {
		h := serve(t, all, answer)
		reply := h.ask(query(t, 3, "www.example.com.", 1), time.Second)
		if reply == nil {
			t.Fatalf("%s: no reply", name)
		}
		if hd := header(t, reply); hd.RCode != dnsmessage.RCodeServerFailure || hd.ID != 3 || !hd.Response {
			t.Errorf("%s: header %+v", name, hd)
		}
	}
}

func TestKernel_MarkedUpstreamSetsMark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	c, err := dialMarked(context.Background(), "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	raw.Control(func(fd uintptr) { mark, err = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) })
	if err != nil || uint32(mark) != fw.DNSMark {
		t.Fatalf("SO_MARK %#x (%v), want %#x", mark, err, fw.DNSMark)
	}
}
