package agent

import (
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xdr/internal/fw"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/rules"
)

// syncTable builds the firewall table from the config and the fleet's
// blocks, applies it when it differs from what is applied, and repairs
// drift. The caller holds a.mu.
func (a *agent) syncTable(now time.Time) {
	drift := func(action, detail string) {
		a.record(incident.Incident{Kind: "fw-drift", Action: action, Severity: model.SevHigh, Detail: detail})
	}
	rules := fw.Build(a.cfg, a.blocks, now)
	if text := rules.String(); text != a.applied {
		// The DNS switch, its expiry or a reload: ours, not drift.
		if err := a.fw.Apply(rules); err != nil {
			drift("alert", "the table could not be applied: "+err.Error())
		} else {
			a.applied = text
		}
	} else if drifted, err := a.fw.Drifted(); err != nil {
		drift("alert", "the table could not be read: "+err.Error())
	} else if drifted {
		if err := a.fw.Apply(rules); err != nil {
			drift("alert", "the table was changed and could not be repaired: "+err.Error())
		} else {
			drift("repaired", "table inet xdr was changed")
		}
	}
}

// blockText is a block as an incident names it: 203.0.113.9:4444/tcp.
func blockText(b fw.Block) string {
	return b.Addr.String() + ":" + strconv.Itoa(int(b.Port)) + "/" + b.Proto
}

// setBlocks takes the blocks of the remote rules in force (kept: the rules
// that passed this box's own checks), says which are new and which are
// gone, and applies the table at once when they changed, so one find is cut
// here as soon as the signed set arrives. The caller holds a.mu.
func (a *agent) setBlocks(kept []rules.Rule) {
	if a.blockSet == nil {
		// What an earlier run of this agent announced is not news.
		a.blockSet = map[fw.Block]bool{}
		saved, err := fw.LoadBlocks(a.blocksPath())
		if err != nil {
			a.logf("blocks: %v", err)
		}
		for _, b := range saved {
			a.blockSet[b] = true
		}
	}
	by := map[fw.Block]rules.Rule{}
	var raw []fw.Block
	for _, r := range kept {
		if r.Kind != "remote" || !r.Addr.IsValid() {
			continue
		}
		b := fw.Block{Addr: r.Addr.Unmap(), Proto: r.Proto, Port: r.Port}
		by[b] = r
		raw = append(raw, b)
	}
	sel, over := fw.Select(a.cfg, raw)
	now := map[fw.Block]bool{}
	var added []fw.Block
	for _, b := range sel {
		now[b] = true
		if !a.blockSet[b] {
			added = append(added, b)
		}
	}
	var gone []fw.Block
	for b := range a.blockSet {
		if !now[b] {
			gone = append(gone, b)
		}
	}
	slices.SortFunc(gone, func(x, y fw.Block) int { return strings.Compare(blockText(x), blockText(y)) })
	if over != a.blocksOver && over > 0 {
		a.record(incident.Incident{Kind: "fw-block-cap", Action: "alert", Severity: model.SevHigh,
			Detail: fmt.Sprintf("%d blocks over the table's limit of %d are not applied", over, fw.MaxBlocks)})
	}
	a.blocksOver = over
	a.blocks, a.blockSet = raw, now
	if len(added) == 0 && len(gone) == 0 {
		return
	}
	at := a.now()
	a.syncTable(at)
	// Told repaired once the table holding them is in; otherwise an alert,
	// and the guard's next tick applies it.
	action, why := "repaired", ""
	if a.applied != fw.Build(a.cfg, a.blocks, at).String() {
		action, why = "alert", " (not yet applied: the table could not be applied)"
	}
	for _, b := range added {
		r := by[b]
		a.record(incident.Incident{Kind: "fw-block", Action: action, Severity: model.SevMedium,
			Detail: fmt.Sprintf("blocked %s: rule %s from %s%s", blockText(b), r.ID, r.From, why)})
	}
	for _, b := range gone {
		a.record(incident.Incident{Kind: "fw-unblock", Action: action, Severity: model.SevMedium, Detail: "unblocked " + blockText(b) + why})
	}
	if err := fw.SaveBlocks(a.blocksPath(), sel); err != nil {
		a.logf("blocks: %v", err)
	}
}

// blocksPath is where the blocks in force are kept.
func (a *agent) blocksPath() string { return filepath.Join(a.state, "blocks.json") }
