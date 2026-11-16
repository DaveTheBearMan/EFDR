package agent

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"xdr/internal/baseline"
	"xdr/internal/classify"
	"xdr/internal/collect"
	"xdr/internal/diff"
	"xdr/internal/fleet"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/pathenc"
)

const (
	// maxDrift is how many findings the agent remembers having reported.
	maxDrift = 4096
	// maxNoise is how many of those may be files nothing classifies
	// (altered or removed): the rest is kept for what matters.
	maxNoise = 1024
	// scanCap is the most findings one scan reports: the controller disables
	// a host that writes over 600 incidents a minute, and the rest follow on
	// the next scans.
	scanCap = 25
	// fastHash is how much of a file the fast scan hashes.
	fastHash = 8 << 20
)

// scanRoots are the directories the fast scan walks: where persistence and
// drop sites live. The whole disk is walked by the full scan.
var scanRoots = []string{"/etc", "/usr/lib/systemd", "/usr/local", "/opt", "/root", "/home", "/var/spool", "/tmp", "/var/tmp", "/dev/shm", "/srv"}

// driftEntry is a new file the agent reported, as it was reported: the
// file order acts only on what is here, and only while it is still so.
type driftEntry struct {
	Path, SHA256, Link string
	Size               int64
	Type               baseline.FileType
}

// FileID is the name of a path in the file order (see fleet.FileID).
func FileID(path string) string { return fleet.FileID(path) }

func underRoots(path string) bool {
	for _, r := range scanRoots {
		if path == r || strings.HasPrefix(path, r+"/") {
			return true
		}
	}
	return false
}

// scanLoop runs the fast scan every Scan.Interval and the full scan every
// Scan.Full, one at a time: a scan still running skips the next tick.
func (a *agent) scanLoop(ctx context.Context, fast, full time.Duration) {
	var running atomic.Bool
	run := func(isFull bool) {
		if !running.CompareAndSwap(false, true) {
			return
		}
		go func() {
			defer running.Store(false)
			a.scan(isFull)
		}()
	}
	run(false)
	f, l := time.NewTicker(fast), time.NewTicker(full)
	defer f.Stop()
	defer l.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-f.C:
			run(false)
		case <-l.C:
			run(true)
		}
	}
}

// scan compares the box with its baseline, the persistence directories
// only or the whole disk, and reports each finding not already reported
// with the same content as a file-drift incident. A fast scan compares
// against the baseline restricted to the directories it walked, so nothing
// outside them reads as removed. The walk holds no lock.
func (a *agent) scan(full bool) {
	a.mu.Lock()
	base, root := a.pol.Base, a.root
	a.mu.Unlock()
	if base == nil {
		return
	}
	var live, ref *baseline.Baseline
	if full {
		var err error
		if live, err = collect.Snapshot(root); err != nil {
			a.logf("scan: %v", err)
			return
		}
		ref = base
	} else {
		files, _ := collect.WalkDirs(root, scanRoots, fastHash)
		live = &baseline.Baseline{Files: files, Accounts: base.Accounts, Groups: base.Groups, Modules: base.Modules}
		ref = &baseline.Baseline{Files: map[string]baseline.FileEntry{}, Accounts: base.Accounts, Groups: base.Groups, Modules: base.Modules}
		for key, e := range base.Files {
			if p, err := pathenc.Decode(key); err == nil && underRoots(p) {
				ref.Files[key] = e
			}
		}
	}
	findings := diff.Diff(ref, live)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.drift == nil {
		a.drift, a.driftNew, a.driftNoise = map[string]string{}, map[string]driftEntry{}, map[string]bool{}
	}
	seen := map[string]bool{}
	reported, waiting, noise := 0, 0, 0
	for p := range a.drift {
		if a.driftNoise[p] {
			noise++
		}
	}
	for _, f := range findings {
		path, err := pathenc.Decode(f.Subject)
		if err != nil || !strings.HasPrefix(path, "/") {
			continue // an account, a group, a module
		}
		if a.manages(path) {
			continue
		}
		// A new file nothing classifies is the box's everyday traffic (/tmp,
		// /home): the exec and connection detections are for what runs.
		unclassified := f.Category == classify.Fallback
		if f.Kind == model.KindAdded && unclassified {
			continue
		}
		seen[path] = true
		e := live.Files[f.Subject]
		fp := string(f.Kind) + "|" + f.Before + "|" + f.After + "|" + f.Detail + "|" + e.SHA256 + "|" + e.Link
		if a.drift[path] == fp {
			continue
		}
		_, known := a.drift[path]
		if !known && (len(a.drift) >= maxDrift || unclassified && noise >= maxNoise) {
			continue
		}
		if reported >= scanCap {
			waiting++
			continue // reported by a later scan
		}
		reported++
		if !known && unclassified {
			noise++
		}
		a.drift[path] = fp
		a.driftNoise[path] = unclassified
		detail := fmt.Sprintf("%s %s: %s", f.Category, f.Kind, f.Detail)
		if len(e.SHA256) >= 12 {
			detail += " (sha256 " + e.SHA256[:12] + ")" // the log folds identical lines: a changed file is a new one
		}
		a.record(incident.Incident{Kind: "file-drift", Action: "alert", Severity: f.Severity, Path: path, SHA256: e.SHA256, Size: e.Size, Detail: detail})
		id := FileID(path)
		if f.Kind == model.KindAdded && (e.Type == baseline.TypeFile || e.Type == baseline.TypeLink) && f.Category != classify.Fallback {
			link, _ := pathenc.Decode(e.Link)
			a.driftNew[id] = driftEntry{Path: path, SHA256: e.SHA256, Link: link, Size: e.Size, Type: e.Type}
		} else {
			delete(a.driftNew, id)
		}
	}
	for path := range a.drift {
		if !seen[path] && (full || underRoots(path)) {
			delete(a.drift, path)
			delete(a.driftNoise, path)
			delete(a.driftNew, FileID(path))
		}
	}
	if waiting > 0 {
		a.record(incident.Incident{Kind: "file-drift", Action: "alert", Severity: model.SevMedium,
			Detail: fmt.Sprintf("%d more findings not reported yet; the next scans report them", waiting)})
	}
}

// manages reports whether the agent itself writes path: the gate's sshd
// and PAM files, and the resolver files with dns.pin. A change there is the
// agent's doing (or reported as ssh-drift / dns-files), not drift. The
// caller holds a.mu.
func (a *agent) manages(path string) bool {
	switch path {
	case "/etc/ssh/sshd_config", "/etc/pam.d/sshd":
		return a.cfg.SSH != nil
	case "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf":
		return a.cfg.DNS.Pin
	}
	return false
}
