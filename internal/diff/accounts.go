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

// diffAccounts compares passwd/shadow state. Either side being nil means it
// was not captured, so nothing is compared.
func diffAccounts(base, live []baseline.Account) []model.Finding {
	if base == nil || live == nil {
		return nil
	}
	var out []model.Finding
	add := func(k model.Kind, sev model.Severity, name, detail, before, after string) {
		out = append(out, model.Finding{Kind: k, Category: "account", Severity: sev, Subject: name, Detail: detail, Before: before, After: after})
	}
	old := map[string]baseline.Account{}
	for _, a := range base {
		old[a.Name] = a
	}
	seen := map[string]bool{}
	for _, l := range live {
		seen[l.Name] = true
		b, ok := old[l.Name]
		if !ok {
			if l.UID == 0 && l.Name != "root" {
				add(model.KindAdded, model.SevCritical, l.Name, "new account with uid 0", "", l.Shell)
			} else {
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
			add(model.KindAltered, model.SevHigh, l.Name, fmt.Sprintf("password changed (%s→%s)", b.PwState, l.PwState), "", "")
		}
		if l.Home != b.Home {
			add(model.KindAltered, model.SevMedium, l.Name, "home changed", b.Home, l.Home)
		}
		if l.GID != b.GID {
			add(model.KindAltered, model.SevMedium, l.Name, fmt.Sprintf("gid %d→%d", b.GID, l.GID), fmt.Sprint(b.GID), fmt.Sprint(l.GID))
		}
	}
	for _, b := range base {
		if !seen[b.Name] {
			add(model.KindRemoved, model.SevMedium, b.Name, "account removed", b.Shell, "")
		}
	}
	return out
}

func diffGroups(base, live []baseline.Group) []model.Finding {
	if base == nil || live == nil {
		return nil
	}
	var out []model.Finding
	old := map[string]baseline.Group{}
	for _, g := range base {
		old[g.Name] = g
	}
	for _, l := range live {
		b, ok := old[l.Name]
		if !ok {
			out = append(out, model.Finding{Kind: model.KindAdded, Category: "group", Severity: model.SevMedium,
				Subject: l.Name, Detail: fmt.Sprintf("new group gid %d", l.GID), After: strings.Join(l.Members, ",")})
			continue
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
			if privilegedGroups[l.Name] {
				sev = model.SevCritical
			}
			out = append(out, model.Finding{Kind: model.KindAltered, Category: "group", Severity: sev,
				Subject: l.Name, Detail: "new member " + m, Before: strings.Join(b.Members, ","), After: strings.Join(l.Members, ",")})
		}
	}
	return out
}

func diffModules(base, live []string) []model.Finding {
	if base == nil || live == nil {
		return nil
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
