package tamper

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
