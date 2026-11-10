package diff

import (
	"fmt"
	"strings"

	"xdr/internal/baseline"
	"xdr/internal/model"
)

// privilegedGroups grant root or root-equivalent access to their members.
var privilegedGroups = map[string]bool{
	"root": true, "sudo": true, "adm": true, "docker": true, "shadow": true, "disk": true, "lxd": true,
}

func nologin(shell string) bool {
	return strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false")
}

// privilegedGIDs maps every gid that grants root-equivalent access to the
// group that makes it so. Membership is decided by number, so a group that
// shares a privileged group's gid is that group.
func privilegedGIDs(groups []baseline.Group) map[uint32]string {
	gids := map[uint32]string{0: "root"}
	for _, g := range groups {
		if !g.Bad && privilegedGroups[g.Name] {
			gids[g.GID] = g.Name
		}
	}
	return gids
}

// notCaptured reports a database the baseline has but the live snapshot
// could not capture: the comparison did not happen.
func notCaptured(category, subject string) []model.Finding {
	return []model.Finding{{Kind: model.KindError, Category: category, Severity: model.SevHigh,
		Subject: subject, Detail: "not captured, so not compared with the baseline"}}
}

// diffAccounts compares passwd/shadow state. A baseline without accounts
// has nothing to compare against.
func diffAccounts(base, live []baseline.Account, privGID map[uint32]string) []model.Finding {
	if base == nil {
		return nil
	}
	if live == nil {
		return notCaptured("account", "/etc/passwd")
	}
	var out []model.Finding
	add := func(k model.Kind, sev model.Severity, name, detail, before, after string) {
		out = append(out, model.Finding{Kind: k, Category: "account", Severity: sev, Subject: name, Detail: detail, Before: before, After: after})
	}
	old, oldBad := map[string]baseline.Account{}, map[string]bool{}
	for _, a := range base {
		if a.Bad {
			oldBad[a.Name] = true
		} else if _, dup := old[a.Name]; !dup {
			old[a.Name] = a // lookups by name return the first entry
		}
	}
	seen := map[string]bool{}
	for _, l := range live {
		if l.Bad {
			if !oldBad[l.Name] {
				add(model.KindAdded, model.SevHigh, l.Name, "malformed passwd line", "", "")
			}
			continue
		}
		seen[l.Name] = true
		b, ok := old[l.Name]
		if !ok {
			switch group, priv := privGID[l.GID]; {
			case l.UID == 0 && l.Name != "root":
				add(model.KindAdded, model.SevCritical, l.Name, "new account with uid 0", "", l.Shell)
			case priv:
				add(model.KindAdded, model.SevCritical, l.Name, fmt.Sprintf("new account uid %d in group %s (gid %d)", l.UID, group, l.GID), "", l.Shell)
			default:
				add(model.KindAdded, model.SevHigh, l.Name, fmt.Sprintf("new account uid %d", l.UID), "", l.Shell)
			}
			continue
		}
		if l.UID != b.UID {
			sev := model.SevHigh
			if l.UID == 0 {
				sev = model.SevCritical
			}
			add(model.KindAltered, sev, l.Name, fmt.Sprintf("uid %d→%d", b.UID, l.UID), fmt.Sprint(b.UID), fmt.Sprint(l.UID))
		}
		if l.Shell != b.Shell {
			sev := model.SevMedium
			if nologin(b.Shell) && !nologin(l.Shell) {
				sev = model.SevHigh
			}
			add(model.KindAltered, sev, l.Name, "shell changed", b.Shell, l.Shell)
		}
		if l.PwState != b.PwState || l.PwDigest != b.PwDigest {
			sev := model.SevHigh
			if l.PwState == "none" && b.PwState != "none" {
				sev = model.SevCritical // logs in with no password
			}
			add(model.KindAltered, sev, l.Name, fmt.Sprintf("password changed (%s→%s)", b.PwState, l.PwState), "", "")
		}
		if l.Home != b.Home {
			add(model.KindAltered, model.SevMedium, l.Name, "home changed", b.Home, l.Home)
		}
		if l.GID != b.GID {
			sev, detail := model.SevMedium, fmt.Sprintf("gid %d→%d", b.GID, l.GID)
			if group, priv := privGID[l.GID]; priv {
				sev, detail = model.SevCritical, detail+" (group "+group+")"
			}
			add(model.KindAltered, sev, l.Name, detail, fmt.Sprint(b.GID), fmt.Sprint(l.GID))
		}
	}
	for _, b := range base {
		if !b.Bad && !seen[b.Name] {
			seen[b.Name] = true
			add(model.KindRemoved, model.SevMedium, b.Name, "account removed", b.Shell, "")
		}
	}
	return out
}

func diffGroups(base, live []baseline.Group) []model.Finding {
	if base == nil {
		return nil
	}
	if live == nil {
		return notCaptured("group", "/etc/group")
	}
	var out []model.Finding
	add := func(k model.Kind, sev model.Severity, name, detail, before, after string) {
		out = append(out, model.Finding{Kind: k, Category: "group", Severity: sev, Subject: name, Detail: detail, Before: before, After: after})
	}
	privGID := privilegedGIDs(live)
	old, oldBad := map[string]baseline.Group{}, map[string]bool{}
	for _, g := range base {
		if g.Bad {
			oldBad[g.Name] = true
		} else if _, dup := old[g.Name]; !dup {
			old[g.Name] = g
		}
	}
	seen := map[string]bool{}
	for _, l := range live {
		if l.Bad {
			if !oldBad[l.Name] {
				add(model.KindAdded, model.SevHigh, l.Name, "malformed group line", "", "")
			}
			continue
		}
		seen[l.Name] = true
		_, priv := privGID[l.GID]
		priv = priv || privilegedGroups[l.Name]
		members := strings.Join(l.Members, ",")
		b, ok := old[l.Name]
		if !ok {
			sev := model.SevMedium
			if priv {
				sev = model.SevCritical
			}
			add(model.KindAdded, sev, l.Name, fmt.Sprintf("new group gid %d", l.GID), "", members)
			continue
		}
		if l.GID != b.GID {
			sev := model.SevHigh
			if priv {
				sev = model.SevCritical
			}
			add(model.KindAltered, sev, l.Name, fmt.Sprintf("gid %d→%d", b.GID, l.GID), fmt.Sprint(b.GID), fmt.Sprint(l.GID))
		}
		had := map[string]bool{}
		for _, m := range b.Members {
			had[m] = true
		}
		for _, m := range l.Members {
			if had[m] {
				continue
			}
			sev := model.SevLow
			if priv {
				sev = model.SevCritical
			}
			add(model.KindAltered, sev, l.Name, "new member "+m, strings.Join(b.Members, ","), members)
		}
	}
	for _, b := range base {
		if !b.Bad && !seen[b.Name] {
			seen[b.Name] = true
			add(model.KindRemoved, model.SevLow, b.Name, "group removed", strings.Join(b.Members, ","), "")
		}
	}
	return out
}

func diffModules(base, live []string) []model.Finding {
	if base == nil {
		return nil
	}
	if live == nil {
		return notCaptured("module", "/proc/modules")
	}
	var out []model.Finding
	inBase, inLive := map[string]bool{}, map[string]bool{}
	for _, m := range base {
		inBase[m] = true
	}
	for _, m := range live {
		inLive[m] = true
		if !inBase[m] {
			out = append(out, model.Finding{Kind: model.KindAdded, Category: "module", Severity: model.SevCritical, Subject: m, Detail: "kernel module loaded"})
		}
	}
	for _, m := range base {
		if !inLive[m] {
			out = append(out, model.Finding{Kind: model.KindRemoved, Category: "module", Severity: model.SevLow, Subject: m, Detail: "kernel module unloaded"})
		}
	}
	return out
}
