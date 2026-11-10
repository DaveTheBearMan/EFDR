package sensor

import (
	"encoding/binary"
	"os"
	"os/exec"
	"testing"
	"time"
)

// procMsg builds a connector message carrying one proc_event.
func procMsg(what, pid, tgid uint32) []byte {
	b := make([]byte, 44)
	le := binary.NativeEndian
	le.PutUint32(b[0:], 1)   // idx: CN_IDX_PROC
	le.PutUint32(b[4:], 1)   // val: CN_VAL_PROC
	le.PutUint16(b[16:], 24) // len
	le.PutUint32(b[20:], what)
	le.PutUint32(b[36:], pid)
	le.PutUint32(b[40:], tgid)
	return b
}

func TestParseProcEvent_Exec(t *testing.T) {
	// A thread that is not the group leader execs: the process is the tgid.
	ev, ok := parseProcEvent(procMsg(2, 4243, 4242))
	if !ok || ev != (Event{Kind: Exec, PID: 4242}) {
		t.Fatalf("%+v %v", ev, ok)
	}
	// The kernel pads the event union: a longer message is the same event.
	if ev, ok := parseProcEvent(append(procMsg(2, 7, 7), make([]byte, 32)...)); !ok || ev.PID != 7 {
		t.Fatalf("padded: %+v %v", ev, ok)
	}
}

func TestParseProcEvent_OtherAndShort(t *testing.T) {
	exec := procMsg(2, 4242, 4242)
	other := procMsg(2, 4242, 4242)
	binary.NativeEndian.PutUint32(other[0:], 9) // some other connector
	for name, b := range map[string][]byte{
		"fork":            procMsg(1, 4242, 4242),
		"exit":            procMsg(0x80000000, 4242, 4242),
		"ack (what 0)":    procMsg(0, 0, 0),
		"short":           exec[:10],
		"one byte short":  exec[:43],
		"empty":           nil,
		"other connector": other,
		"pid 0":           procMsg(2, 0, 0),
	} {
		if ev, ok := parseProcEvent(b); ok {
			t.Errorf("%s: %+v", name, ev)
		}
	}
}

func TestKernel_ProcConnSeesExec(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root")
	}
	src, err := NewProcConn()
	if err != nil {
		t.Fatal(err)
	}
	if src.Name() != "proc" {
		t.Fatalf("name %q", src.Name())
	}
	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	want := cmd.Process.Pid
	timeout := time.After(2 * time.Second)
	for seen := false; !seen; {
		select {
		case ev := <-src.Events():
			seen = ev.Kind == Exec && ev.PID == want
		case <-timeout:
			t.Fatalf("no exec event for pid %d", want)
		}
	}
	if err := src.Close(); err != nil {
		t.Fatal(err)
	}
	// Close ends the stream.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-src.Events():
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("events channel still open after Close")
		}
	}
}
