// Package guard is the watcher process: two of them run as different units
// and each keeps the other, the agent and every launch point alive.
package guard

import (
	"context"
	"slices"
	"strings"
	"time"

	"xdr/internal/install"
)

// Tick is one look: ensure puts back what differs from the manifest and
// starts the units that are not running, and the watched unit (the other
// guard) is started if ensure did not already. report is told what was done.
func Tick(l install.Layout, run install.Runner, watch string, report func(string)) {
	rep, err := install.Ensure(l, run)
	for _, p := range rep.Restored {
		report("restored " + p)
	}
	for _, u := range rep.Started {
		report("started " + u)
	}
	if err != nil {
		report("ensure: " + err.Error())
	}
	if slices.Contains(rep.Started, watch) {
		return
	}
	if out, _ := run("systemctl", "is-active", watch); strings.TrimSpace(string(out)) != "active" {
		if _, err := run("systemctl", "start", watch, "--no-block"); err == nil {
			report("started " + watch)
		}
	}
}

// Run looks every `every` until ctx is done.
func Run(ctx context.Context, l install.Layout, run install.Runner, watch string, every time.Duration, report func(string)) {
	Tick(l, run, watch, report)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			Tick(l, run, watch, report)
		}
	}
}
