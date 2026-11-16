package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/collect"
	"xdr/internal/incident"
	"xdr/internal/install"
	"xdr/internal/model"
	"xdr/internal/sshgate"
)

// onToken is a break-glass use over the gate socket.
func (a *agent) onToken(m sshgate.Msg) sshgate.Reply {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.useToken(m.Token, m.Session, true)
}

// useToken applies a token: an approve-session token approves session,
// once; a pause token holds kills and gate ends until it expires. Refusals
// are recorded when loud (a socket use, not a spool rescan).
func (a *agent) useToken(s, session string, loud bool) sshgate.Reply {
	refuse := func(why string) sshgate.Reply {
		if loud {
			a.record(incident.Incident{Kind: "breakglass", Action: "alert", Severity: model.SevHigh, Detail: "refused: " + why})
		}
		return sshgate.Reply{Why: why}
	}
	if a.tokenPub == nil {
		return refuse("this box has no rule key to check tokens with")
	}
	t, err := breakglass.Parse(s, a.tokenPub)
	if err == nil {
		err = t.Valid(a.cfg.Host, a.now())
	}
	if err != nil {
		return refuse(err.Error())
	}
	a.loadUsed()
	_, seen := a.used[t.ID]
	switch t.Action {
	case "uninstall":
		if seen {
			return sshgate.Reply{Why: "token used"}
		}
		return a.uninstall(t)
	case "approve-session":
		if seen {
			return sshgate.Reply{Why: "token used"}
		}
		if session == "" {
			return refuse("no session to approve")
		}
		if a.approved == nil {
			a.approved = map[string]bool{}
		}
		a.approved[session] = true
		a.saveOrders()
	case "pause":
		if t.Expires.After(a.pausedUntil) {
			a.pausedUntil = t.Expires
		}
		if seen {
			return sshgate.Reply{OK: true, Why: "paused"}
		}
	}
	a.used[t.ID] = t.Expires
	a.saveUsed()
	detail := fmt.Sprintf("%s token %s for %s", t.Action, t.ID, t.Host)
	if session != "" {
		detail += ", session " + session
	}
	a.record(incident.Incident{Kind: "breakglass", Action: "alert", Severity: model.SevHigh, Detail: detail})
	return sshgate.Reply{OK: true, Why: t.Action}
}

// uninstall removes the install for a valid uninstall token, once. The
// incident is recorded (and given a moment to leave, with a.mu held) before
// anything is removed; install.Uninstall stops the agent's own unit last, so
// the guards cannot bring it back and the removal is not cut short.
func (a *agent) uninstall(t breakglass.Token) sshgate.Reply {
	// a.mu is held, so a second use cannot start while this runs. The id is
	// spent only once the removal worked: a failed one may be retried.
	a.record(incident.Incident{Kind: "uninstall", Action: "uninstalled", Severity: model.SevCritical,
		Detail: fmt.Sprintf("a signed break-glass token (%s) removed the XDR install from %s", t.ID, t.Host)})
	if a.settle != nil {
		a.settle()
	}
	if a.runner == nil {
		return sshgate.Reply{Why: "no install to remove"}
	}
	if err := install.Uninstall(a.layout, a.runner); err != nil {
		a.record(incident.Incident{Kind: "uninstall", Action: "alert", Severity: model.SevCritical, Detail: "uninstall failed: " + err.Error()})
		return sshgate.Reply{Why: "uninstall failed: " + err.Error()}
	}
	a.used[t.ID] = t.Expires
	a.saveUsed()
	if a.exit != nil {
		a.exit()
	}
	return sshgate.Reply{OK: true, Why: "uninstalled"}
}

// scanSpool applies tokens left in the spool, so ones written while the
// agent was down take effect, and deletes the files that can never be
// valid here (not a token, not the rule key's, another host's, expired):
// anyone may put files in the spool, and they must not pile up.
func (a *agent) scanSpool() {
	for _, f := range breakglass.ReadSpoolFiles(a.spool) {
		e := breakglass.ParseEntry(f.Content)
		if a.tokenPub != nil {
			t, err := breakglass.Parse(e.Token, a.tokenPub)
			if err != nil || t.Host != a.cfg.Host || a.now().After(t.Expires.Add(breakglass.Skew)) {
				os.Remove(filepath.Join(a.spool, f.Name))
				continue
			}
		}
		a.useToken(e.Token, e.Session, false)
	}
}

func (a *agent) usedPath() string { return filepath.Join(a.state, "breakglass-used.json") }

// loadUsed reads the token ids used so far, once; expired ones are dropped.
func (a *agent) loadUsed() {
	if a.used != nil {
		return
	}
	a.used = map[string]time.Time{}
	if b, err := collect.ReadFile(a.usedPath(), 1<<20); err == nil {
		json.Unmarshal(b, &a.used)
	}
	for id, exp := range a.used {
		if a.now().After(exp.Add(breakglass.Skew)) {
			delete(a.used, id)
		}
	}
}

func (a *agent) saveUsed() {
	b, _ := json.Marshal(a.used)
	if err := os.MkdirAll(a.state, 0o700); err == nil {
		tmp := a.usedPath() + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil && os.Rename(tmp, a.usedPath()) == nil {
			return
		}
	}
	a.logf("breakglass: cannot save used token ids; a reuse after a restart would be accepted")
}

// makeSpool makes the spool: anyone may drop a token, nobody else's can be
// read or removed.
func makeSpool(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// Its parent, the state directory, must be passable by everyone (not
	// readable: the files in it are root's alone).
	parent := filepath.Dir(dir)
	if st, err := os.Stat(parent); err == nil && st.Mode().Perm()&0o011 != 0o011 {
		if err := os.Chmod(parent, st.Mode().Perm()|0o711); err != nil {
			return err
		}
	}
	return os.Chmod(dir, os.ModeSticky|0o733)
}
