// Package breakglass is the way back in: tokens minted in advance on the
// jump box, each for one host and one action, and the spool on the box
// where they wait for the agent and the gate.
package breakglass

import (
	"os"
	"slices"
	"time"

	"xdr/internal/collect"
)

// Spool is where `xdr breakglass` leaves tokens: anyone may add one
// (sticky, write-only for others), only root may list it.
const Spool = "/var/lib/xdr/breakglass"

const (
	spoolFiles = 64
	spoolFile  = 4 << 10
	spoolScan  = 4096 // directory entries looked at, at most
)

// ReadSpool is the content of the newest files in dir: at most 64, each at
// most 4 KiB; larger ones are skipped.
func ReadSpool(dir string) []string {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	ents, _ := f.ReadDir(spoolScan)
	type cand struct {
		name string
		mod  time.Time
	}
	var cs []cand
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() > spoolFile {
			continue
		}
		cs = append(cs, cand{e.Name(), info.ModTime()})
	}
	slices.SortFunc(cs, func(a, b cand) int { return b.mod.Compare(a.mod) })
	var out []string
	for _, c := range cs {
		if len(out) == spoolFiles {
			break
		}
		if b, err := collect.ReadFile(dir+"/"+c.name, spoolFile); err == nil {
			out = append(out, string(b))
		}
	}
	return out
}
