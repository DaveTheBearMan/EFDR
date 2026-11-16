// Package breakglass is the way back in: tokens minted in advance on the
// jump box, each for one host and one action, and the spool on the box
// where they wait for the agent and the gate.
package breakglass

import (
	"os"
	"path/filepath"

	"xdr/internal/collect"
)

// Spool is where `xdr breakglass` leaves tokens: anyone may add one
// (sticky, write-only for others), only root may list it.
const Spool = "/var/lib/xdr/breakglass"

const (
	spoolFile = 4 << 10
	spoolScan = 4096 // directory entries looked at, at most
)

// SpoolFile is one file of the spool.
type SpoolFile struct{ Name, Content string }

// ReadSpoolFiles reads the spool: at most 4096 entries, regular files of
// at most 4 KiB, none opened by anything but a no-follow read. It does not
// pick the newest or the first: anyone may create files here and date
// them as they like, so a limit by age or order would let junk hide a real
// token. Every one is verified by the caller, and the agent deletes the
// ones that fail.
func ReadSpoolFiles(dir string) []SpoolFile {
	f, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer f.Close()
	ents, _ := f.ReadDir(spoolScan)
	var out []SpoolFile
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if info, err := e.Info(); err != nil || info.Size() > spoolFile {
			continue
		}
		if b, err := collect.ReadFile(filepath.Join(dir, e.Name()), spoolFile); err == nil {
			out = append(out, SpoolFile{e.Name(), string(b)})
		}
	}
	return out
}

// ReadSpool is the content of the files ReadSpoolFiles reads.
func ReadSpool(dir string) []string {
	var out []string
	for _, f := range ReadSpoolFiles(dir) {
		out = append(out, f.Content)
	}
	return out
}
