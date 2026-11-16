// Package console is the operator's view of the fleet and the web server
// that shows it: what the agents detected and did, what needs a person,
// each host's state, and the credentials the jump box rotated.
package console

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"xdr/internal/controller"
	"xdr/internal/fleet"
	"xdr/internal/incident"
	"xdr/internal/rules"
)

var (
	// ErrHandled is Handle's error for an approval already dealt with.
	ErrHandled = errors.New("already handled")
	// ErrUnknown is Handle's error for an approval that is not there.
	ErrUnknown = errors.New("unknown approval")
)

const (
	maxIncidents = 2000
	maxHandled   = 500
	maxText      = 2048
	maxHosts     = 256
	maxAlerts    = 200
	maxSessions  = 50
	stepWindow   = 60 * time.Second
	undoWindow   = 24 * time.Hour
)

// Summary is the strip of numbers on top of the page.
type Summary struct {
	Need, Killed, AgentsUp, AgentsTotal, Blocks int
}

// Alert is one incident, as the page shows it.
type Alert struct {
	ID, Host, Kind, Action, Severity, Title, Detail, Exe, SHA256, Path, Remote string
	Chain, Steps                                                               []string
	Time                                                                       time.Time
}

// Approval is something that needs the operator.
type Approval struct {
	ID, Host, Kind, Title, Why string
	Deadline                   time.Time
	Actions                    []string
	Params                     map[string]string
	Time                       time.Time
}

// SessionRow is one line of the sessions table.
type SessionRow struct {
	Host, ID, User, From, Status string
	Time                         time.Time
}

// HostRow is one line of the hosts table.
type HostRow struct {
	Name, Status string // up, silent, never, disabled
	Last         time.Time
	Kill         string // the kill switch as its agent last reported it: on, off, or "" (the config decides)
	Drift        int    // files that differ from the baseline and are not dealt with
	Alerts       int    // incidents in the last hour
}

// View is everything the page shows.
type View struct {
	Now       time.Time
	Summary   Summary
	Alerts    []Alert
	Approvals []Approval
	Sessions  []SessionRow
	Hosts     []HostRow
	Rules     int
}

type handledEntry struct {
	ID     string    `json:"id"`
	Action string    `json:"action"`
	At     time.Time `json:"at"`
}

// State is the view's memory: the last incidents and which approvals were
// dealt with. Only the second is kept across a restart (the controller
// replays its incident log to fill the first).
type State struct {
	mu      sync.Mutex
	dir     string
	now     func() time.Time
	ring    []incident.Incident
	handled map[string]handledEntry
	order   []string
	modes   map[string]string // host → the kill switch its agent last reported (on, off)
}

// NewState reads dir's console-state.json.
func NewState(dir string, now func() time.Time) (*State, error) {
	s := &State{dir: dir, now: now, handled: map[string]handledEntry{}}
	b, err := os.ReadFile(filepath.Join(dir, "console-state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f struct {
		Handled []handledEntry `json:"handled"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("console-state.json: %w", err)
	}
	for _, h := range f.Handled {
		s.handled[h.ID] = h
		s.order = append(s.order, h.ID)
	}
	s.trimHandled()
	return s, nil
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// Feed takes in one incident.
func (s *State) Feed(in incident.Incident) {
	in.Detail, in.Path, in.Exe, in.User, in.Comm = cut(in.Detail, maxText), cut(in.Path, maxText), cut(in.Exe, maxText), cut(in.User, 64), cut(in.Comm, 128)
	in.Host, in.Kind, in.Action = cut(in.Host, 128), cut(in.Kind, 64), cut(in.Action, 32)
	if len(in.Chain) > 16 {
		in.Chain = in.Chain[:16]
	}
	chain := make([]incident.ProcRef, len(in.Chain))
	for i, c := range in.Chain {
		chain[i] = incident.ProcRef{PID: c.PID, Comm: cut(c.Comm, 128), Exe: cut(c.Exe, 512)}
	}
	in.Chain, in.Cmdline = chain, nil
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.Time.IsZero() {
		in.Time = s.now()
	}
	if in.Kind == "mode" && (in.Action == "kill-on" || in.Action == "kill-off") {
		if s.modes == nil {
			s.modes = map[string]string{}
		}
		if _, ok := s.modes[in.Host]; ok || len(s.modes) < 4*maxHosts {
			s.modes[in.Host] = strings.TrimPrefix(in.Action, "kill-")
		}
	}
	s.ring = append(s.ring, in)
	if len(s.ring) > maxIncidents {
		s.ring = s.ring[len(s.ring)-maxIncidents:]
	}
}

// LoadLog fills the view from the tail of the controller's incident log,
// so a restart does not start with an empty page.
func (s *State) LoadLog(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	const tail = 4 << 20
	skipFirst := false
	if st.Size() > tail {
		if _, err := f.Seek(st.Size()-tail, io.SeekStart); err != nil {
			return err
		}
		skipFirst = true
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for first := true; sc.Scan(); first = false {
		if first && skipFirst {
			continue // a line cut in half
		}
		var in incident.Incident
		if json.Unmarshal(sc.Bytes(), &in) == nil {
			s.Feed(in)
		}
	}
	return nil
}

// Len is how many incidents are held.
func (s *State) Len() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.ring) }

// HandledLen is how many handled approvals are remembered.
func (s *State) HandledLen() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.handled) }

func (s *State) trimHandled() {
	for len(s.order) > maxHandled {
		delete(s.handled, s.order[0])
		s.order = s.order[1:]
	}
}

func (s *State) save() error {
	var f struct {
		Handled []handledEntry `json:"handled"`
	}
	for _, id := range s.order {
		f.Handled = append(f.Handled, s.handled[id])
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "console-state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "console-state.json"))
}

// Handle marks an approval dealt with (action is what was done) and says
// what it was. Doing it twice is ErrHandled.
func (s *State) Handle(id, action string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found *Approval
	d := s.derive()
	for i := range d.approvals {
		if d.approvals[i].ID == id {
			found = &d.approvals[i]
		}
	}
	if found == nil {
		if _, done := s.handled[id]; done {
			return Approval{}, ErrHandled
		}
		return Approval{}, ErrUnknown
	}
	s.handled[id] = handledEntry{ID: id, Action: action, At: s.now()}
	s.order = slices.DeleteFunc(s.order, func(x string) bool { return x == id })
	s.order = append(s.order, id)
	s.trimHandled()
	if err := s.save(); err != nil {
		delete(s.handled, id)
		s.order = slices.DeleteFunc(s.order, func(x string) bool { return x == id })
		return Approval{}, err
	}
	return *found, nil
}

// covered says whether an incident at `at` is one the handled entry for aid
// covers: only what was pending when it was handled. The same id can name
// something new later (session numbers restart at every boot, a removed
// file can return).
func (s *State) covered(aid string, at time.Time) (handledEntry, bool) {
	h, ok := s.handled[aid]
	return h, ok && !at.After(h.At)
}

// Unhandle takes an approval back to pending, for an order that could not be put.
func (s *State) Unhandle(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.handled[id]; !ok {
		return
	}
	delete(s.handled, id)
	s.order = slices.DeleteFunc(s.order, func(x string) bool { return x == id })
	s.save()
}

// Peek is the approval with that id as it stands, handled or not found: ok false.
func (s *State) Peek(id string) (Approval, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.derive().approvals {
		if a.ID == id {
			return a, true
		}
	}
	return Approval{}, false
}

var (
	sessionRe = regexp.MustCompile(`session (\S+) from (\S+)`)
	endsRe    = regexp.MustCompile(`\(ends in ([^)]+)\)`)
	blockRe   = regexp.MustCompile(`^blocked (\S+): rule`)
	ruleRe    = regexp.MustCompile(`rule (\S+)`)

	sessionOnly = regexp.MustCompile(`session (\S+)`)
)

type derived struct {
	approvals []Approval
	sessions  []SessionRow
	blocks    int
	drift     map[string]int
}

func sid(detail string) (id, from string) {
	m := sessionRe.FindStringSubmatch(detail)
	if m == nil {
		return "", ""
	}
	return m[1], strings.TrimSuffix(m[2], ":")
}

// newFile reports whether a drift detail ("<category> added: new file ...")
// is a new file or symlink in a persistence category: the only kind the
// agent will remove. A new file nothing classifies ("file") is not.
func newFile(detail string) bool {
	f := strings.Fields(detail)
	if len(f) < 4 || f[0] == "file" || f[1] != "added:" || f[2] != "new" {
		return false
	}
	return f[3] == "file" || f[3] == "symlink"
}

// derive reads the ring from oldest to newest and keeps what is still true.
func (s *State) derive() derived {
	now := s.now()
	approvals := map[string]*Approval{}
	var order []string
	put := func(a Approval) {
		if _, ok := approvals[a.ID]; !ok {
			order = append(order, a.ID)
		}
		approvals[a.ID] = &a
	}
	del := func(id string) { delete(approvals, id) }
	rows := map[string]*SessionRow{}
	var rowOrder []string
	row := func(host, id string) *SessionRow {
		k := host + "/" + id
		if rows[k] == nil {
			rows[k] = &SessionRow{Host: host, ID: id}
			rowOrder = append(rowOrder, k)
		}
		return rows[k]
	}
	blocked := map[string]map[string]bool{} // host → endpoints
	driftPaths := map[string]map[string]bool{}
	for _, in := range s.ring {
		switch in.Kind {
		case "session-pending":
			id, from := sid(in.Detail)
			if id == "" {
				continue
			}
			aid := "s:" + in.Host + ":" + id
			r := row(in.Host, id)
			r.User, r.From, r.Time, r.Status = in.User, from, in.Time, "pending"
			if h, done := s.covered(aid, in.Time); done {
				r.Status = map[string]string{"approve": "approved", "kill": "ended"}[h.Action]
				if r.Status == "" {
					r.Status = h.Action
				}
				continue
			}
			var deadline time.Time
			if m := endsRe.FindStringSubmatch(in.Detail); m != nil {
				if d, err := time.ParseDuration(m[1]); err == nil {
					deadline = in.Time.Add(d)
				}
			}
			put(Approval{ID: aid, Host: in.Host, Kind: "session", Title: fmt.Sprintf("%s from %s", in.User, from),
				Why:    "Not approved yet. The session is ended when the timer reaches zero.",
				Params: map[string]string{"session": id}, Actions: []string{"approve", "kill"}, Deadline: deadline, Time: in.Time})
		case "session-terminated", "session-refused":
			if id, from := sid(in.Detail); id != "" {
				del("s:" + in.Host + ":" + id)
				r := row(in.Host, id)
				r.User, r.From, r.Time, r.Status = in.User, from, in.Time, "ended"
			}
		case "session":
			if id, from := sid(in.Detail); id != "" {
				r := row(in.Host, id)
				r.User, r.From, r.Time, r.Status = in.User, from, in.Time, "login"
			}
		case "breakglass":
			if m := sessionOnly.FindStringSubmatch(in.Detail); m != nil {
				del("s:" + in.Host + ":" + m[1])
				row(in.Host, m[1]).Status = "approved"
			}
		case "user-disabled", "user-new":
			aid := "u:" + in.Host + ":" + in.User
			if _, done := s.covered(aid, in.Time); done || in.User == "" {
				continue
			}
			why := "Not in the baseline."
			if in.Kind == "user-disabled" {
				why = "Not in the baseline; the agent locked it. Approving unlocks it."
			}
			put(Approval{ID: aid, Host: in.Host, Kind: "user", Title: fmt.Sprintf("User %s (%s)", in.User, in.Detail), Why: why,
				Params: map[string]string{"user": in.User}, Actions: []string{"approve", "ignore"}, Time: in.Time})
		case "user-enabled":
			del("u:" + in.Host + ":" + in.User)
		case "file-drift":
			if in.Path == "" {
				continue
			}
			if driftPaths[in.Host] == nil {
				driftPaths[in.Host] = map[string]bool{}
			}
			driftPaths[in.Host][in.Path] = true
			aid := "f:" + in.Host + ":" + fleet.FileID(in.Path)
			if !newFile(in.Detail) {
				del(aid)
				continue
			}
			if _, done := s.covered(aid, in.Time); done {
				continue
			}
			put(Approval{ID: aid, Host: in.Host, Kind: "file", Title: "New file " + in.Path, Why: in.Detail,
				Params: map[string]string{"path": in.Path, "sha256": in.SHA256}, Actions: []string{"remove", "keep"}, Time: in.Time})
		case "file-removed":
			fid := fleet.FileID(in.Path)
			del("f:" + in.Host + ":" + fid)
			delete(driftPaths[in.Host], in.Path)
			if aid := "fu:" + in.Host + ":" + fid; in.Time.Add(undoWindow).After(now) {
				if _, done := s.covered(aid, in.Time); !done {
					put(Approval{ID: aid, Host: in.Host, Kind: "file", Title: "Removed " + in.Path, Why: "Kept in quarantine; it can be put back until the deadline.",
						Params: map[string]string{"path": in.Path}, Actions: []string{"undo"}, Deadline: in.Time.Add(undoWindow), Time: in.Time})
				}
			}
		case "file-restored":
			del("fu:" + in.Host + ":" + fleet.FileID(in.Path))
		case "proc-killed":
			for id := range approvals {
				if strings.HasPrefix(id, "p:"+in.Host+":"+strconv.Itoa(in.PID)+":") {
					del(id)
				}
			}
		case "fw-block":
			if m := blockRe.FindStringSubmatch(in.Detail); m != nil {
				if blocked[in.Host] == nil {
					blocked[in.Host] = map[string]bool{}
				}
				blocked[in.Host][m[1]] = true
			}
		case "fw-unblock":
			delete(blocked[in.Host], strings.TrimPrefix(in.Detail, "unblocked "))
		}
		if in.Action == "held" && in.PID > 0 && len(in.SHA256) >= 12 {
			aid := "p:" + in.Host + ":" + strconv.Itoa(in.PID) + ":" + in.SHA256[:12]
			if _, done := s.covered(aid, in.Time); !done {
				put(Approval{ID: aid, Host: in.Host, Kind: "proc", Title: fmt.Sprintf("%s (pid %d) held: %s", in.Kind, in.PID, in.Exe),
					Why:    "Held because it is a scored service. Killing it takes the service offline until it is restarted. " + in.Detail,
					Params: map[string]string{"pid": strconv.Itoa(in.PID), "sha256": in.SHA256, "exe": in.Exe, "user": in.User}, Actions: []string{"kill", "ignore"}, Time: in.Time})
			}
		}
	}
	var d derived
	for _, id := range order {
		if a := approvals[id]; a != nil {
			d.approvals = append(d.approvals, *a)
		}
	}
	slices.SortStableFunc(d.approvals, func(a, b Approval) int { return b.Time.Compare(a.Time) })
	for _, k := range rowOrder {
		d.sessions = append(d.sessions, *rows[k])
	}
	slices.SortStableFunc(d.sessions, func(a, b SessionRow) int { return b.Time.Compare(a.Time) })
	if len(d.sessions) > maxSessions {
		d.sessions = d.sessions[:maxSessions]
	}
	all := map[string]bool{}
	for _, eps := range blocked {
		for e := range eps {
			all[e] = true
		}
	}
	d.blocks = len(all)
	d.drift = map[string]int{}
	for h, ps := range driftPaths {
		d.drift[h] = len(ps)
	}
	return d
}

// View is the page's data now: hosts from the controller, the rule set in force.
func (s *State) View(hosts []controller.HostStatus, set *rules.Set) View {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	d := s.derive()
	v := View{Now: now, Approvals: d.approvals, Sessions: d.sessions}
	if set != nil {
		v.Rules = len(set.Rules)
	}
	if len(hosts) > maxHosts {
		hosts = hosts[:maxHosts]
	}
	recent := map[string]int{}
	for _, in := range s.ring {
		if in.Action == "killed" {
			v.Summary.Killed++
		}
		if now.Sub(in.Time) < time.Hour && in.Action != "" {
			recent[in.Host]++
		}
	}
	for _, h := range hosts {
		r := HostRow{Name: h.Name, Last: h.Last, Kill: s.modes[h.Name], Drift: d.drift[h.Name], Alerts: recent[h.Name]}
		switch {
		case h.Disabled:
			r.Status = "disabled"
		case h.Silent:
			r.Status = "silent"
		case !h.Seen:
			r.Status = "never"
		default:
			r.Status = "up"
			v.Summary.AgentsUp++
		}
		v.Hosts = append(v.Hosts, r)
	}
	v.Summary.AgentsTotal = len(hosts)
	v.Summary.Blocks = d.blocks
	for _, a := range d.approvals {
		if !slices.Contains(a.Actions, "undo") {
			v.Summary.Need++
		}
	}
	// Alerts, newest first, each with what followed it.
	for i := len(s.ring) - 1; i >= 0 && len(v.Alerts) < maxAlerts; i-- {
		in := s.ring[i]
		if in.Kind == "session-pending" || in.Kind == "console-action" {
			continue
		}
		v.Alerts = append(v.Alerts, s.alert(i))
	}
	return v
}

func (s *State) alert(i int) Alert {
	in := s.ring[i]
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s", in.Host, in.Kind, in.Time.UnixNano(), in.Detail)))
	a := Alert{ID: hex.EncodeToString(sum[:6]), Host: in.Host, Kind: in.Kind, Action: in.Action, Severity: in.Severity.String(),
		Title: in.Kind + " · " + in.Action, Detail: in.Detail, Exe: in.Exe, SHA256: in.SHA256, Path: in.Path, Time: in.Time}
	if in.Remote != nil {
		a.Remote = fmt.Sprintf("%s:%d/%s", in.Remote.Addr, in.Remote.Port, in.Remote.Proto)
	}
	for _, c := range in.Chain {
		a.Chain = append(a.Chain, fmt.Sprintf("%s (pid %d)", c.Comm, c.PID))
	}
	switch in.Action {
	case "killed":
		a.Steps = append(a.Steps, "killed")
	case "held":
		a.Steps = append(a.Steps, "held: a scored service")
	case "would-kill":
		a.Steps = append(a.Steps, "would have been killed (kill is off)")
	case "kill-failed":
		a.Steps = append(a.Steps, "the kill failed")
	}
	if in.SHA256 == "" && a.Remote == "" {
		return a
	}
	var blockedOn []string
	for _, later := range s.ring[i+1:] {
		if later.Time.Sub(in.Time) > stepWindow {
			break
		}
		switch later.Kind {
		case "rule-promoted":
			if (in.SHA256 != "" && later.SHA256 == in.SHA256) || (a.Remote != "" && strings.Contains(later.Detail, a.Remote)) {
				if m := ruleRe.FindStringSubmatch(later.Detail); m != nil {
					a.Steps = append(a.Steps, "rule "+m[1]+" written")
				}
			}
		case "fw-block":
			if a.Remote != "" && strings.Contains(later.Detail, "blocked "+a.Remote+":") && !slices.Contains(blockedOn, later.Host) {
				blockedOn = append(blockedOn, later.Host)
			}
		}
	}
	if len(blockedOn) > 0 {
		a.Steps = append(a.Steps, "blocked on "+strings.Join(blockedOn, ", "))
	}
	return a
}
