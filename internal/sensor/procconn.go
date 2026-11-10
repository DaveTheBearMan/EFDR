package sensor

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The kernel's process events connector (linux/cn_proc.h).
const (
	cnIdxProc       = 1
	cnValProc       = 1
	procMcastListen = 1
	procEventExec   = 2

	cnMsgLen     = 20 // idx, val, seq, ack u32; len, flags u16
	procEventHdr = 16 // what, cpu u32; timestamp u64
)

type procConn struct {
	conn   *netlink.Conn
	events chan Event
	once   sync.Once
	done   chan struct{}
}

// NewProcConn listens for exec events on the netlink proc connector. It
// is what the agent falls back to without eBPF: it knows only that a pid
// exec'd, and the event may come late or, under load, not at all.
func NewProcConn() (Source, error) {
	conn, err := netlink.Dial(unix.NETLINK_CONNECTOR, &netlink.Config{Groups: cnIdxProc})
	if err != nil {
		return nil, err
	}
	sub := make([]byte, cnMsgLen+4)
	binary.NativeEndian.PutUint32(sub[0:], cnIdxProc)
	binary.NativeEndian.PutUint32(sub[4:], cnValProc)
	binary.NativeEndian.PutUint16(sub[16:], 4)
	binary.NativeEndian.PutUint32(sub[cnMsgLen:], procMcastListen)
	if _, err := conn.Send(netlink.Message{Header: netlink.Header{Type: netlink.Done}, Data: sub}); err != nil {
		conn.Close()
		return nil, err
	}
	p := &procConn{conn: conn, events: make(chan Event, 1024), done: make(chan struct{})}
	go p.run()
	return p, nil
}

func (p *procConn) Name() string         { return "proc" }
func (p *procConn) Events() <-chan Event { return p.events }

func (p *procConn) Close() error {
	var err error
	p.once.Do(func() {
		err = p.conn.Close()
		<-p.done
	})
	return err
}

func (p *procConn) run() {
	defer close(p.done)
	defer close(p.events)
	for {
		msgs, err := p.conn.Receive()
		if errors.Is(err, unix.ENOBUFS) {
			continue // events were lost; the sweep covers the gap
		}
		if err != nil {
			return
		}
		for _, m := range msgs {
			if ev, ok := parseProcEvent(m.Data); ok {
				select {
				case p.events <- ev:
				default: // nobody is keeping up; the sweep covers this too
				}
			}
		}
	}
}

// parseProcEvent reads one connector message, reporting whether it is an
// exec. The process is the thread group, whichever thread called exec.
func parseProcEvent(b []byte) (Event, bool) {
	if len(b) < cnMsgLen+procEventHdr+8 {
		return Event{}, false
	}
	le := binary.NativeEndian
	if le.Uint32(b[0:]) != cnIdxProc || le.Uint32(b[4:]) != cnValProc || le.Uint32(b[cnMsgLen:]) != procEventExec {
		return Event{}, false
	}
	tgid := le.Uint32(b[cnMsgLen+procEventHdr+4:])
	if tgid == 0 || tgid > 1<<22 {
		return Event{}, false
	}
	return Event{Kind: Exec, PID: int(tgid)}, true
}
