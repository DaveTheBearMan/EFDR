package dnsguard

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	"xdr/internal/fw"
)

const (
	maxPacket       = 65535
	maxInFlight     = 64
	upstreamTimeout = 2 * time.Second
)

// Query is one well-formed question put to the stub.
type Query struct {
	Name    string         // lower case, no trailing dot
	Type    uint16         //
	Client  netip.AddrPort // loopback source; the agent maps the port to a process
	Allowed bool
}

// Stub is the only resolver on the box. A name on the allow list is
// forwarded upstream; every other name does not exist.
type Stub struct {
	Allowed  func(name string) bool                              // exact name match
	Upstream func(ctx context.Context, q []byte) ([]byte, error) // one UDP exchange with the resolver
	OnQuery  func(Query)                                         // every well-formed query, before its reply
}

// Serve answers queries arriving on pc until ctx is done.
func (s *Stub) Serve(ctx context.Context, pc net.PacketConn) error {
	stop := context.AfterFunc(ctx, func() { pc.SetReadDeadline(time.Now()) })
	defer stop()
	slots := make(chan struct{}, maxInFlight)
	buf := make([]byte, maxPacket)
	for {
		n, from, err := pc.ReadFrom(buf)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			continue // flooded: the asker retries
		}
		packet := append([]byte(nil), buf[:n]...)
		go func() {
			defer func() { <-slots }()
			if reply := s.answer(ctx, packet, from); reply != nil {
				pc.WriteTo(reply, from)
			}
		}()
	}
}

// answer returns the reply to one packet, or nil when it gets none.
func (s *Stub) answer(ctx context.Context, packet []byte, from net.Addr) []byte {
	h, q, ok := parseQuery(packet)
	if !ok {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	allowed := s.Allowed != nil && s.Allowed(name)
	if s.OnQuery != nil {
		var client netip.AddrPort
		if ua, ok := from.(*net.UDPAddr); ok {
			client = ua.AddrPort()
			client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		}
		s.OnQuery(Query{Name: name, Type: uint16(q.Type), Client: client, Allowed: allowed})
	}
	if !allowed {
		return reply(h, q, dnsmessage.RCodeNameError)
	}
	if s.Upstream == nil {
		return reply(h, q, dnsmessage.RCodeServerFailure)
	}
	ans, err := s.Upstream(ctx, packet)
	if err != nil || !answers(ans, h, q) {
		return reply(h, q, dnsmessage.RCodeServerFailure)
	}
	return ans
}

// parseQuery accepts a standard query with exactly one question.
func parseQuery(packet []byte) (dnsmessage.Header, dnsmessage.Question, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(packet)
	if err != nil || h.Response || h.OpCode != 0 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return h, dnsmessage.Question{}, false
	}
	q, err := p.Question()
	return h, q, err == nil
}

// answers reports whether ans is a response to the question q asked under h.
func answers(ans []byte, h dnsmessage.Header, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	ah, err := p.Start(ans)
	if err != nil || !ah.Response || ah.ID != h.ID || binary.BigEndian.Uint16(ans[4:6]) != 1 {
		return false
	}
	aq, err := p.Question()
	return err == nil && aq.Type == q.Type && aq.Class == q.Class &&
		strings.EqualFold(aq.Name.String(), q.Name.String())
}

func reply(h dnsmessage.Header, q dnsmessage.Question, code dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
		RCode:              code,
	})
	if b.StartQuestions() != nil || b.Question(q) != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// MarkedUpstream returns an Upstream that asks resolver over UDP from a
// socket carrying fw.DNSMark, the one mark the firewall lets out to port 53.
func MarkedUpstream(resolver netip.Addr) func(context.Context, []byte) ([]byte, error) {
	addr := netip.AddrPortFrom(resolver, 53).String()
	return func(ctx context.Context, q []byte) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
		defer cancel()
		c, err := dialMarked(ctx, addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
		defer stop()
		if _, err := c.Write(q); err != nil {
			return nil, err
		}
		buf := make([]byte, maxPacket)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
}

func dialMarked(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fw.DNSMark))
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return d.DialContext(ctx, "udp", addr)
}
