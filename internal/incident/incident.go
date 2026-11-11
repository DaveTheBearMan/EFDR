// Package incident is the agent's record of what it detected and did: one
// JSON object per line, appended to a file only root can read.
package incident

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"xdr/internal/model"
)

// maxString is the most bytes of any one string that are recorded.
const maxString = 4096

// Endpoint is the far end of a connection.
type Endpoint struct {
	Addr  string `json:"addr"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

// ProcRef names one process in an incident's ancestry.
type ProcRef struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
}

// Incident is one detection and the response to it.
type Incident struct {
	Time      time.Time      `json:"time"`
	Host      string         `json:"host,omitempty"`
	Kind      string         `json:"kind"`
	Action    string         `json:"action"` // killed | held | alert | would-kill | kill-failed | repaired
	Severity  model.Severity `json:"severity"`
	PID       int            `json:"pid,omitempty"`
	UID       uint32         `json:"uid"`
	User      string         `json:"user,omitempty"`
	Comm      string         `json:"comm,omitempty"`
	Exe       string         `json:"exe,omitempty"`
	SHA256    string         `json:"sha256,omitempty"`
	Cmdline   []string       `json:"cmdline,omitempty"`
	Cgroup    string         `json:"cgroup,omitempty"`
	Container string         `json:"container,omitempty"`
	Origin    string         `json:"origin,omitempty"`
	Chain     []ProcRef      `json:"chain,omitempty"`
	Remote    *Endpoint      `json:"remote,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Count     int            `json:"count"` // identical incidents this line stands for
}

// foldKey is what makes two incidents the same one happening again.
type foldKey struct {
	kind, action, exe string
	pid               int // kills only: each kill is its own line
	uid               uint32
	remote            Endpoint
	hasRemote         bool
	detail            string
}

type folded struct {
	written time.Time // when a line for this key was last written
	held    int       // repeats since, not yet on any line
}

// Log appends incidents to a file, folding repeats.
type Log struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	size   int64
	window time.Duration
	now    func() time.Time
	seen   map[foldKey]*folded

	// OnWrite, when set, is called with every incident as it was written.
	OnWrite func(Incident)
	// MaxSize bounds the file: a line that would take it past MaxSize
	// first moves it to path.1, replacing the one there.
	MaxSize int64
}

// DefaultMaxSize is MaxSize as Open sets it.
const DefaultMaxSize = 64 << 20

func openFile(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// rotate moves the file to path.1 and starts a new one.
func (l *Log) rotate() error {
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	f, size, err := openFile(l.path)
	if err != nil {
		return err
	}
	l.f.Close()
	l.f, l.size = f, size
	return nil
}

// Open opens the log at path for appending, creating it (0600) and its
// directory (0700) as needed. An incident repeated within window of the
// line last written for it is counted instead of written.
func Open(path string, window time.Duration) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, size, err := openFile(path)
	if err != nil {
		return nil, err
	}
	return &Log{path: path, f: f, size: size, window: window, now: time.Now, seen: map[foldKey]*folded{}, MaxSize: DefaultMaxSize}, nil
}

// Close closes the file.
func (l *Log) Close() error { return l.f.Close() }

// Add records in, stamping the time when it has none. It reports whether a
// line was written; a repeat inside the window is only counted, and the
// next line written for it carries the count.
func (l *Log) Add(in Incident) (written bool, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	in = clean(in)
	if in.Time.IsZero() {
		in.Time = now
	}
	key := foldKey{kind: in.Kind, action: in.Action, exe: in.Exe, uid: in.UID, detail: in.Detail}
	if in.Remote != nil {
		key.remote, key.hasRemote = *in.Remote, true
	}
	if in.Action == "killed" || in.Action == "kill-failed" {
		key.pid = in.PID
	}
	prev := l.seen[key]
	if prev != nil && now.Sub(prev.written) < l.window {
		prev.held++
		return false, nil
	}
	in.Count = 1
	if prev != nil {
		in.Count += prev.held
	}
	line, err := json.Marshal(in)
	if err != nil {
		return false, err
	}
	line = append(line, '\n')
	if l.MaxSize > 0 && l.size > 0 && l.size+int64(len(line)) > l.MaxSize {
		if err := l.rotate(); err != nil {
			return false, err
		}
	}
	n, err := l.f.Write(line)
	l.size += int64(n)
	if err != nil {
		return false, err
	}
	if len(l.seen) >= 4096 {
		for k, v := range l.seen {
			if now.Sub(v.written) >= l.window {
				delete(l.seen, k)
			}
		}
	}
	l.seen[key] = &folded{written: now}
	if l.OnWrite != nil {
		l.OnWrite(in)
	}
	return true, nil
}

// clean returns in with every string cut to maxString bytes of valid UTF-8.
func clean(in Incident) Incident {
	for _, s := range []*string{&in.Host, &in.Kind, &in.Action, &in.User, &in.Comm, &in.Exe, &in.SHA256, &in.Cgroup, &in.Container, &in.Origin, &in.Detail} {
		*s = cut(*s)
	}
	if in.Cmdline != nil {
		args := make([]string, len(in.Cmdline))
		for i, a := range in.Cmdline {
			args[i] = cut(a)
		}
		in.Cmdline = args
	}
	if in.Chain != nil {
		chain := make([]ProcRef, len(in.Chain))
		for i, p := range in.Chain {
			chain[i] = ProcRef{PID: p.PID, Comm: cut(p.Comm), Exe: cut(p.Exe)}
		}
		in.Chain = chain
	}
	if in.Remote != nil {
		in.Remote = &Endpoint{Addr: cut(in.Remote.Addr), Port: in.Remote.Port, Proto: cut(in.Remote.Proto)}
	}
	return in
}

func cut(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= maxString {
		return s
	}
	n := maxString
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// Read decodes a log. A line that does not decode is skipped; the error
// says how many were.
func Read(r io.Reader) ([]Incident, error) {
	var out []Incident
	bad := 0
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var in Incident
			if json.Unmarshal(line, &in) == nil {
				out = append(out, in)
			} else {
				bad++
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
	}
	if bad > 0 {
		return out, fmt.Errorf("%d unreadable lines skipped", bad)
	}
	return out, nil
}
