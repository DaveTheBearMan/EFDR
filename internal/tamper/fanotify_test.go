package tamper

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func next(t *testing.T, w *Watcher, within time.Duration) (Event, bool) {
	t.Helper()
	select {
	case ev := <-w.Events():
		return ev, true
	case <-time.After(within):
		return Event{}, false
	}
}

func drain(w *Watcher) []Event {
	var out []Event
	for {
		select {
		case ev := <-w.Events():
			out = append(out, ev)
		case <-time.After(300 * time.Millisecond):
			return out
		}
	}
}

// Run as root (make test-root): fanotify needs it.
func TestKernel_TamperWatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	root := t.TempDir()
	shared := filepath.Join(root, "shared") // a directory with one watched file among others
	whole := filepath.Join(root, "whole")   // a directory watched in full
	os.MkdirAll(shared, 0o755)
	os.MkdirAll(whole, 0o755)
	watched := filepath.Join(shared, "xdr.unit")
	os.WriteFile(watched, []byte("a"), 0o644)
	os.WriteFile(filepath.Join(shared, "other.txt"), []byte("a"), 0o644)
	w, err := Watch([]string{watched, filepath.Join(root, "missing/file")}, []string{whole})
	if err != nil && w == nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.Skipped() == 0 {
		t.Error("a missing path was not reported as skipped")
	}
	pid := os.Getpid()

	os.WriteFile(watched, []byte("changed"), 0o644)
	ev, ok := next(t, w, 2*time.Second)
	if !ok || ev.PID != pid || ev.Path != watched {
		t.Fatalf("write: %+v %v", ev, ok)
	}
	drain(w)

	os.WriteFile(filepath.Join(shared, "other.txt"), []byte("b"), 0o644)
	if evs := drain(w); len(evs) != 0 {
		t.Fatalf("an unwatched sibling raised %+v", evs)
	}

	os.WriteFile(filepath.Join(whole, "new"), []byte("x"), 0o644)
	var created bool
	for _, e := range drain(w) {
		created = created || (e.Path == filepath.Join(whole, "new") && e.PID == pid)
	}
	if !created {
		t.Fatal("a file created in a fully watched directory raised nothing")
	}

	os.Rename(watched, watched+".moved")
	var moved bool
	for _, e := range drain(w) {
		moved = moved || (e.Path == watched && e.PID == pid)
	}
	if !moved {
		t.Fatal("a rename of a watched file raised nothing")
	}
	os.Rename(watched+".moved", watched)
	drain(w)
	os.Remove(watched)
	var deleted bool
	for _, e := range drain(w) {
		deleted = deleted || (e.Path == watched && e.PID == pid && e.Op != "")
	}
	if !deleted {
		t.Fatal("a delete of a watched file raised nothing")
	}
}

// The kernel's queue overflow, and an event the full channel had no room
// for, are counted.
func TestParse_CountsDrops(t *testing.T) {
	w := &Watcher{events: make(chan Event), paths: map[string]bool{}, dirs: map[string]bool{"/d": true}, byHandle: map[string]string{}}
	md := unix.FanotifyEventMetadata{Mask: unix.FAN_Q_OVERFLOW, Fd: -1}
	md.Event_len = uint32(unsafe.Sizeof(md))
	md.Metadata_len = uint16(md.Event_len)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&md)), md.Event_len)
	w.parse(append(append([]byte{}, b...), b...))
	if w.Dropped() != 2 {
		t.Fatalf("overflow: %d", w.Dropped())
	}
}

// A writer that has exited by the time its event is read is said to be
// gone: by the kernel (no pidfd) or by its pidfd. One still running is not.
func TestKernel_TamperPidfd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	dir := t.TempDir()
	watched := filepath.Join(dir, "xdr.unit")
	os.WriteFile(watched, []byte("a"), 0o644)
	w, err := Watch([]string{watched}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if !w.PidFDs() {
		t.Fatal("this kernel takes FAN_REPORT_PIDFD, but the watcher fell back")
	}
	// This process writes and still runs.
	os.WriteFile(watched, []byte("b"), 0o644)
	ev, ok := next(t, w, 2*time.Second)
	if !ok || ev.PID != os.Getpid() || ev.Gone() {
		t.Fatalf("live writer: %+v %v gone=%v", ev, ok, ev.Gone())
	}
	ev.Close()
	drain(w)
	// A child writes and exits before the event is looked at.
	c := exec.Command("sh", "-c", "echo c > "+watched)
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	ev, ok = next(t, w, 2*time.Second)
	if !ok || ev.PID != c.Process.Pid || !ev.Gone() {
		t.Fatalf("exited writer: %+v %v gone=%v", ev, ok, ev.Gone())
	}
	ev.Close()
}

// A kernel that refuses FAN_REPORT_PIDFD gets the flags of before: events
// carry the pid alone and are never said to be gone.
func TestWatch_FallsBackWithoutPidfd(t *testing.T) {
	var calls []uint
	defer func(f func(uint, uint) (int, error)) { fanotifyInit = f }(fanotifyInit)
	fanotifyInit = func(flags, evFlags uint) (int, error) {
		calls = append(calls, flags)
		if flags&unix.FAN_REPORT_PIDFD != 0 {
			return -1, unix.EINVAL
		}
		return unix.Eventfd(0, unix.EFD_CLOEXEC) // something to close; marks on it fail
	}
	w, err := Watch(nil, []string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if len(calls) != 2 || calls[0]&unix.FAN_REPORT_PIDFD == 0 || calls[1] != calls[0]&^unix.FAN_REPORT_PIDFD {
		t.Fatalf("init flags %x", calls)
	}
	if w.PidFDs() {
		t.Fatal("PidFDs after the fallback")
	}
	if (Event{PID: 1}).Gone() {
		t.Fatal("an event without a pidfd is gone")
	}
}

// Gone reads a pidfd: an exited child's shows it, a live one's does not.
func TestEvent_GoneByPidfd(t *testing.T) {
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.PidfdOpen(c.Process.Pid, 0)
	if err != nil {
		c.Process.Kill()
		t.Skip("no pidfd_open:", err)
	}
	ev := Event{PID: c.Process.Pid, Writer: os.NewFile(uintptr(fd), "pidfd")}
	defer ev.Close()
	if ev.Gone() {
		t.Fatal("a running writer is gone")
	}
	c.Process.Kill()
	c.Wait()
	if !ev.Gone() {
		t.Fatal("an exited writer is not gone")
	}
	if !(Event{PID: 5, Exited: true}).Gone() {
		t.Fatal("Exited is not gone")
	}
}
