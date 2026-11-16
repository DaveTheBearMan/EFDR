package sshgate

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Socket is where the agent hears the gate. Anyone may connect: a message
// is a session lookup or a signed token.
const Socket = "/run/xdr/gate.sock"

const (
	maxMsg   = 8 << 10
	deadline = 2 * time.Second
	maxConns = 64
)

// Msg is one request to the agent: a session opening (from pam_exec) or a
// break-glass token (from `xdr breakglass`).
type Msg struct {
	Session, User, RHost, Token string
	PPID                        int
}

// Reply is the agent's answer.
type Reply struct {
	OK  bool
	Why string
}

// Serve answers each connection on l with handle, one message per
// connection, until ctx is done.
func Serve(ctx context.Context, l net.Listener, handle func(Msg) Reply) {
	go func() { <-ctx.Done(); l.Close() }()
	slots := make(chan struct{}, maxConns)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			c.Close() // the gate fails closed on its side
			continue
		}
		go func() {
			defer func() { <-slots }()
			defer c.Close()
			c.SetDeadline(time.Now().Add(deadline))
			r := Reply{Why: "bad message"}
			if m, err := readMsg(c); err == nil {
				r = handle(m)
			}
			b, _ := json.Marshal(r)
			c.Write(append(b, '\n'))
		}()
	}
}

func readMsg(c net.Conn) (Msg, error) {
	var m Msg
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 1024), maxMsg)
	if !sc.Scan() {
		return m, errors.New("no message")
	}
	return m, json.Unmarshal(sc.Bytes(), &m)
}

// Send sends m to the agent at sock and returns its reply.
func Send(sock string, m Msg) (Reply, error) {
	var r Reply
	c, err := net.DialTimeout("unix", sock, deadline)
	if err != nil {
		return r, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(deadline))
	b, _ := json.Marshal(m)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return r, err
	}
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 1024), maxMsg)
	if !sc.Scan() {
		return r, errors.New("no reply")
	}
	return r, json.Unmarshal(sc.Bytes(), &r)
}

// Check is `xdr gate`, run by pam_exec as a session opens: nil lets the
// session open. The agent must say yes; if it cannot be reached, only a
// pause token (paused) lets the session through.
func Check(env map[string]string, sock string, paused func() bool) error {
	if env["PAM_TYPE"] != "open_session" {
		return nil
	}
	r, err := Send(sock, Msg{Session: env["XDG_SESSION_ID"], User: env["PAM_USER"], RHost: env["PAM_RHOST"], PPID: os.Getppid()})
	if err != nil {
		if paused() {
			return nil
		}
		return errors.New("gate: agent unreachable")
	}
	if !r.OK {
		return fmt.Errorf("gate: refused: %s", r.Why)
	}
	return nil
}
