// Package tamper tells the agent who touched its files: a fanotify group
// reports each change to the installed files with the pid that made it.
package tamper

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Event is one change: the file (or the directory entry) and who did it.
type Event struct {
	Path string
	Op   string // modify, close-write, attrib, create, delete, moved-from, moved-to, delete-self, move-self (joined with +)
	PID  int
}

// Watcher is a running fanotify group.
type Watcher struct {
	f        *os.File
	events   chan Event
	paths    map[string]bool   // files whose every change is reported
	dirs     map[string]bool   // directories whose every entry is
	byHandle map[string]string // a directory's file handle → its path
	skipped  int
	dropped  atomic.Uint64 // events lost: the kernel's queue overflowed, or the channel was full
}

const mask = unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_ATTRIB | unix.FAN_CREATE | unix.FAN_DELETE |
	unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO | unix.FAN_DELETE_SELF | unix.FAN_MOVE_SELF | unix.FAN_EVENT_ON_CHILD

var ops = []struct {
	bit  uint64
	name string
}{
	{unix.FAN_MODIFY, "modify"}, {unix.FAN_CLOSE_WRITE, "close-write"}, {unix.FAN_ATTRIB, "attrib"}, {unix.FAN_CREATE, "create"},
	{unix.FAN_DELETE, "delete"}, {unix.FAN_MOVED_FROM, "moved-from"}, {unix.FAN_MOVED_TO, "moved-to"},
	{unix.FAN_DELETE_SELF, "delete-self"}, {unix.FAN_MOVE_SELF, "move-self"},
}

// Watch reports every change to each of paths, and every entry change in
// each of dirs. A directory that cannot be marked (it is missing) is
// skipped: Skipped says how many. The parent directory of each path is
// marked, but only changes to the path itself are reported.
func Watch(paths, dirs []string) (*Watcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK|unix.FAN_REPORT_DFID_NAME, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}
	w := &Watcher{f: os.NewFile(uintptr(fd), "fanotify"), events: make(chan Event, 256),
		paths: map[string]bool{}, dirs: map[string]bool{}, byHandle: map[string]string{}}
	marked := map[string]bool{}
	mark := func(dir string) {
		if marked[dir] {
			return
		}
		marked[dir] = true
		h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, dir, 0)
		if err == nil {
			err = unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, dir)
		}
		if err != nil {
			w.skipped++
			return
		}
		w.byHandle[handleKey(h.Bytes(), h.Type())] = dir
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		w.paths[p] = true
		mark(filepath.Dir(p))
	}
	for _, d := range dirs {
		d = filepath.Clean(d)
		w.dirs[d] = true
		mark(d)
	}
	go w.read()
	return w, nil
}

// Events delivers the changes; it is closed when the watcher is.
func (w *Watcher) Events() <-chan Event { return w.events }

// Skipped is how many directories could not be marked.
func (w *Watcher) Skipped() int { return w.skipped }

// Dropped is how many events were lost so far: each overflow of the
// kernel's queue counts one, as does each event the channel had no room for.
func (w *Watcher) Dropped() uint64 { return w.dropped.Load() }

func (w *Watcher) noteDrop() { w.dropped.Add(1) }

// Close stops the watcher.
func (w *Watcher) Close() error { return w.f.Close() }

func handleKey(b []byte, typ int32) string { return fmt.Sprintf("%d:%x", typ, b) }

func (w *Watcher) read() {
	defer close(w.events)
	buf := make([]byte, 64<<10)
	for {
		n, err := w.f.Read(buf)
		if err != nil {
			return
		}
		w.parse(buf[:n])
	}
}

func (w *Watcher) parse(buf []byte) {
	const head = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for off := 0; off+head <= len(buf); {
		md := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[off]))
		end := off + int(md.Event_len)
		if int(md.Event_len) < head || end > len(buf) {
			return
		}
		if md.Fd >= 0 {
			unix.Close(int(md.Fd))
		}
		dir, name := w.where(buf[off+int(md.Metadata_len) : end])
		off = end
		if md.Mask&unix.FAN_Q_OVERFLOW != 0 {
			w.noteDrop()
			continue
		}
		if dir == "" {
			continue
		}
		full := dir
		if name != "" {
			full = filepath.Join(dir, name)
		}
		if !w.paths[full] && !w.dirs[dir] {
			continue
		}
		var which []string
		for _, o := range ops {
			if md.Mask&o.bit != 0 {
				which = append(which, o.name)
			}
		}
		select {
		case w.events <- Event{Path: full, Op: strings.Join(which, "+"), PID: int(md.Pid)}:
		default: // a flood: the first of it was seen
			w.noteDrop()
		}
	}
}

// where reads the directory and entry name out of an event's info records.
func (w *Watcher) where(info []byte) (dir, name string) {
	for len(info) >= 4 {
		typ, l := info[0], int(binary.NativeEndian.Uint16(info[2:4]))
		if l < 4 || l > len(info) {
			return
		}
		if typ == unix.FAN_EVENT_INFO_TYPE_DFID_NAME || typ == unix.FAN_EVENT_INFO_TYPE_DFID {
			rec := info[4:l]
			if len(rec) >= 16 {
				hb := int(binary.NativeEndian.Uint32(rec[8:12]))
				ht := int32(binary.NativeEndian.Uint32(rec[12:16]))
				if 16+hb <= len(rec) {
					dir = w.byHandle[handleKey(rec[16:16+hb], ht)]
					if typ == unix.FAN_EVENT_INFO_TYPE_DFID_NAME {
						rest := rec[16+hb:]
						if i := strings.IndexByte(string(rest), 0); i >= 0 {
							rest = rest[:i]
						}
						name = string(rest)
					}
				}
			}
		}
		info = info[l:]
	}
	return
}
