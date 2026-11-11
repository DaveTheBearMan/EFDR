package sensor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go tool bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" sensor bpf/sensor.c

// eventLen is the size of struct event in bpf/sensor.c.
const eventLen = 184

type bpfSource struct {
	objs  sensorObjects
	links []link.Link
	rd    interface {
		Read() (ringbuf.Record, error)
		Close() error
	}
	pause  func(time.Duration) // time.Sleep; tests replace it
	events chan Event
	once   sync.Once
	done   chan struct{}
}

// NewEBPF loads the sensor programs and attaches them: exec and socket
// tracepoints, and connect and sendmsg hooks on the cgroup at cgroupPath
// (the root of the cgroup v2 tree covers every process, containers
// included). On any error nothing is left attached.
func NewEBPF(cgroupPath string) (Source, error) {
	b := &bpfSource{events: make(chan Event, 4096), done: make(chan struct{}), pause: time.Sleep}
	if err := loadSensorObjects(&b.objs, nil); err != nil {
		return nil, err
	}
	if err := b.attach(cgroupPath); err != nil {
		b.release()
		return nil, err
	}
	go b.run()
	return b, nil
}

func (b *bpfSource) attach(cgroupPath string) error {
	for _, tp := range []struct {
		group, name string
		prog        *ebpf.Program
	}{
		{"sched", "sched_process_exec", b.objs.Exec},
		{"syscalls", "sys_enter_socket", b.objs.Sock},
	} {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			return err
		}
		b.links = append(b.links, l)
	}
	for _, cg := range []struct {
		at   ebpf.AttachType
		prog *ebpf.Program
	}{
		{ebpf.AttachCGroupInet4Connect, b.objs.Connect4},
		{ebpf.AttachCGroupInet6Connect, b.objs.Connect6},
		{ebpf.AttachCGroupUDP4Sendmsg, b.objs.Sendmsg4},
		{ebpf.AttachCGroupUDP6Sendmsg, b.objs.Sendmsg6},
	} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: cg.at, Program: cg.prog})
		if err != nil {
			return err
		}
		b.links = append(b.links, l)
	}
	rd, err := ringbuf.NewReader(b.objs.Events)
	if err != nil {
		return err
	}
	b.rd = rd
	return nil
}

// release detaches and unloads everything.
func (b *bpfSource) release() error {
	var errs []error
	if b.rd != nil {
		errs = append(errs, b.rd.Close())
	}
	for _, l := range b.links {
		errs = append(errs, l.Close())
	}
	errs = append(errs, b.objs.Close())
	return errors.Join(errs...)
}

func (b *bpfSource) Name() string         { return "ebpf" }
func (b *bpfSource) Events() <-chan Event { return b.events }

func (b *bpfSource) Close() error {
	var err error
	b.once.Do(func() {
		err = b.release() // closing the reader ends run
		<-b.done
	})
	return err
}

// maxBackoff caps the pause between failed ring-buffer reads.
const maxBackoff = time.Second

func (b *bpfSource) run() {
	defer close(b.done)
	defer close(b.events)
	backoff := time.Millisecond
	for {
		rec, err := b.rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			b.pause(backoff)
			backoff = min(2*backoff, maxBackoff)
			continue
		}
		backoff = time.Millisecond
		if ev, ok := decode(rec.RawSample); ok {
			select {
			case b.events <- ev:
			default: // nobody is keeping up; the sweep covers the gap
			}
		}
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// decode reads one struct event.
func decode(b []byte) (Event, bool) {
	if len(b) < eventLen {
		return Event{}, false
	}
	le := binary.LittleEndian
	ev := Event{
		Kind: Kind(le.Uint32(b[0:])),
		PID:  int(le.Uint32(b[4:])),
		UID:  le.Uint32(b[12:]),
		Comm: cstr(b[40:56]),
	}
	family, typ := int(le.Uint16(b[16:])), int(le.Uint16(b[18:]))
	if ev.PID <= 0 {
		return Event{}, false
	}
	switch ev.Kind {
	case Exec:
		ev.PPID = int(le.Uint32(b[8:]))
		ev.Filename = cstr(b[56:184])
	case Connect, Send:
		var addr netip.Addr
		switch family {
		case unix.AF_INET:
			addr = netip.AddrFrom4([4]byte(b[24:28]))
		case unix.AF_INET6:
			addr = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		default:
			return Event{}, false
		}
		switch typ {
		case unix.IPPROTO_TCP:
			ev.Proto = "tcp"
		case unix.IPPROTO_UDP:
			ev.Proto = "udp"
		default:
			return Event{}, false // a ping socket: echo is allowed out
		}
		ev.Dst = netip.AddrPortFrom(addr, le.Uint16(b[20:]))
	case Socket:
		ev.Family, ev.SockType = family, typ
	default:
		return Event{}, false
	}
	return ev, true
}
