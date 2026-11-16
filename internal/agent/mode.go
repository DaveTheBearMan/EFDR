package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xdr/internal/collect"
	"xdr/internal/fleet"
	"xdr/internal/incident"
	"xdr/internal/model"
)

// modeAhead is how far ahead of this box's clock a mode order may be put.
const modeAhead = 5 * time.Minute

// killMode is the operator's kill switch, from the controller's `mode`
// order: it stands in for the config's kill until the next order. It is
// kept in State/mode.json, so a restart or a config reload keeps it.
type killMode struct {
	Kill bool      `json:"kill"`
	At   time.Time `json:"at"`
	By   string    `json:"by,omitempty"`
}

// killOn is whether a kill decided is carried out: the operator's latest
// mode order, else the config. A pause and every protection still come
// first (respond.Decide, a.kill). The caller holds a.mu.
func (a *agent) killOn() bool {
	if a.mode != nil {
		return a.mode.Kill
	}
	return a.cfg.Kill
}

func (a *agent) modePath() string { return filepath.Join(a.state, "mode.json") }

// onMode takes in a `mode` order. Unlike a file or proc order it is state:
// the latest by its time holds, and one older than that is ignored. A
// malformed one, or one put more than modeAhead in the future, is ignored
// and reported once. The caller holds a.mu.
func (a *agent) onMode(o fleet.Order) {
	if o.Deleted {
		return // nothing deletes an order; the mode held stays
	}
	var v struct {
		Kill *bool     `json:"kill"`
		At   time.Time `json:"at"`
		By   string    `json:"by"`
	}
	why := ""
	switch {
	case json.Unmarshal(o.Value, &v) != nil:
		why = "not a mode order"
	case v.Kill == nil:
		why = "no kill"
	case v.At.IsZero():
		why = "no time"
	case v.At.After(a.now().Add(modeAhead)):
		why = "put " + v.At.UTC().Format(time.RFC3339) + ", in the future"
	}
	if why != "" {
		if a.modeSaid != string(o.Value) {
			a.modeSaid = string(o.Value)
			a.record(incident.Incident{Kind: "mode-refused", Action: "alert", Severity: model.SevMedium,
				Detail: fmt.Sprintf("mode order ignored: %s: %q", why, cleanBy(string(o.Value)))})
		}
		return
	}
	if a.mode != nil && !v.At.After(a.mode.At) {
		if v.At.Before(a.mode.At) {
			a.logf("order mode: put %s, before the one applied (%s); ignored", v.At.UTC().Format(time.RFC3339Nano), a.mode.At.UTC().Format(time.RFC3339Nano))
		}
		return // the same order, replayed on a connect
	}
	m := killMode{Kill: *v.Kill, At: v.At, By: cleanBy(v.By)}
	a.mode = &m
	a.saveMode()
	act, word := "kill-off", "off"
	if m.Kill {
		act, word = "kill-on", "on"
	}
	by := m.By
	if by == "" {
		by = "the controller"
	}
	a.record(incident.Incident{Kind: "mode", Action: act, Severity: model.SevMedium,
		Detail: fmt.Sprintf("kill turned %s by the operator's order from %s, put %s", word, by, m.At.UTC().Format(time.RFC3339))})
}

// cleanBy keeps text from an order (who put it) printable and bounded.
func cleanBy(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = strings.ToValidUTF8(s[:128], "")
	}
	return s
}

// saveMode writes the mode held, atomically, root only. The caller holds a.mu.
func (a *agent) saveMode() {
	b, _ := json.Marshal(a.mode)
	if err := os.MkdirAll(a.state, 0o700); err == nil {
		tmp := a.modePath() + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil && os.Chmod(tmp, 0o600) == nil && os.Rename(tmp, a.modePath()) == nil {
			return
		}
		os.Remove(tmp)
	}
	a.logf("mode: cannot save %s", a.modePath())
}

// loadMode reads the mode kept before a restart; with none (or a damaged
// file) the config decides.
func (a *agent) loadMode() {
	a.mode = nil
	b, err := collect.ReadFile(a.modePath(), 1<<16)
	if err != nil {
		return
	}
	var m killMode
	if json.Unmarshal(b, &m) != nil || m.At.IsZero() {
		a.logf("mode: %s is damaged; the config decides", a.modePath())
		return
	}
	a.mode = &m
}
