// Package sensor delivers process and network events as they happen.
package sensor

import "net/netip"

// Kind says what a process did.
type Kind int

const (
	Exec Kind = iota + 1
	Connect
	Send
	Socket
)

// Event is one thing one process did.
type Event struct {
	Kind      Kind
	PID, PPID int // PPID is 0 when the source does not know it
	UID       uint32
	Comm      string
	Filename  string         // Exec: the path executed, "" when unknown
	Dst       netip.AddrPort // Connect, Send; v4-mapped addresses are unmapped
	Proto     string         // "tcp", "udp"
	Family    int            // Socket
	SockType  int            // Socket
}

// Source is a running sensor.
type Source interface {
	Name() string
	Events() <-chan Event
	Close() error
}
