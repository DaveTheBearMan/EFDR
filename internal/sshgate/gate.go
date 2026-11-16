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

	"golang.org/x/sys/unix"
)

// Socket is where the agent hears the gate. Anyone may connect: a message
// is a session lookup or a signed token.
const Socket = "/run/xdr/gate.sock"

const (
	maxMsg   = 8 << 10
	deadline = 2 * time.Second
	// Root's connections (the gate runs as root) have slots of their own,
	// so that no other user can hold them all.
	maxConns     = 64
	nonRootConns = 8
	nonRootWait  = 500 * time.Millisecond
)

// isRoot decides whose connections count as the gate's.
var isRoot = func(uid uint32) bool { return uid == 0 }

// Msg is one request to the agent: a session opening (from pam_exec) or a
// break-glass token (from `xdr breakglass`).
type Msg struct {
	Session, User, RHost, Token string
	PPID                        int
	// PeerUID and PeerPID are the connecting process's, from the kernel
	// (SO_PEERCRED): Serve sets them; a client cannot send them.
	PeerUID uint32 `json:"-"`
	PeerPID int    `json:"-"`
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
	rootSlots, otherSlots := make(chan struct{}, maxConns), make(chan struct{}, nonRootConns)
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		uid, pid := peerCred(c)
		slots, wait := otherSlots, nonRootWait
		if isRoot(uid) {
			slots, wait = rootSlots, deadline
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
			c.SetDeadline(time.Now().Add(wait))
			r := Reply{Why: "bad message"}
			if m, err := readMsg(c); err == nil {
				m.PeerUID, m.PeerPID = uid, pid
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

// peerCred is the uid and pid of the process at the other end, from the
// kernel; an unreadable one is nobody (uid 1<<31), never root.
func peerCred(c net.Conn) (uint32, int) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 1 << 31, 0
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 1 << 31, 0
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || cerr != nil {
		return 1 << 31, 0
	}
	return cred.Uid, int(cred.Pid)
}
