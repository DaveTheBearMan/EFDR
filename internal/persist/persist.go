// Package persist finds what started a process: the systemd unit file
// behind its cgroup, or the crontab line cron ran it for.
package persist

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"xdr/internal/collect"
	"xdr/internal/proc"
)

// UnitDirs are where systemd loads unit files from, first match wins.
var UnitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/run/systemd/transient", "/lib/systemd/system", "/usr/lib/systemd/system"}

// CronFiles are the system crontab and the directories of crontabs.
var CronFiles = []string{"/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"}

const maxFile = 1 << 20

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// UnitFile finds the file systemd loaded unit name from under root and
// returns its path on the box and its hash. A template instance
// (getty@tty1.service) falls back to its template (getty@.service). A
// symlinked unit file is an error, not followed.
func UnitFile(root, name string) (string, string, error) {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return "", "", errors.New("bad unit name")
	}
	names := []string{name}
	if at := strings.IndexByte(name, '@'); at > 0 {
		if dot := strings.LastIndexByte(name, '.'); dot > at+1 {
			names = append(names, name[:at+1]+name[dot:])
		}
	}
	for _, n := range names {
		for _, d := range UnitDirs {
			p := path.Join(d, n)
			b, err := collect.ReadFile(filepath.Join(root, p), maxFile)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", "", err
			}
			return p, sum(b), nil
		}
	}
	return "", "", fs.ErrNotExist
}

// CronCommand is the command cron ran for chain[0], read from the first
// process in chain (process first, then its ancestors) that is a shell
// run by cron as [shell, "-c", CMD]. It is "" when cron is not in the
// chain.
func CronCommand(chain []*proc.Proc) string {
	for i := 0; i+1 < len(chain); i++ {
		p, parent := chain[i], chain[i+1]
		if parent == nil || p == nil || parent.Comm != "cron" {
			continue
		}
		if c := p.Cmdline; len(c) == 3 && c[1] == "-c" && proc.Class(c[0], "") == "shell" {
			return c[2]
		}
	}
	return ""
}

// StockCron reads the crontabs under root once and returns whether a
// command appears on a line of one whose hash isBase reports.
func StockCron(root string, isBase func(sha string) bool) func(command string) bool {
	var lines []string
	read := func(p string) {
		b, err := collect.ReadFile(p, maxFile)
		if err != nil || isBase == nil || !isBase(sum(b)) {
			return
		}
		lines = append(lines, strings.Split(string(b), "\n")...)
	}
	for _, f := range CronFiles {
		p := filepath.Join(root, f)
		st, err := os.Lstat(p)
		switch {
		case err != nil:
		case st.Mode().IsRegular():
			read(p)
		case st.IsDir():
			ents, _ := os.ReadDir(p)
			for _, e := range ents {
				if e.Type().IsRegular() {
					read(filepath.Join(p, e.Name()))
				}
			}
		}
	}
	return func(command string) bool {
		if strings.TrimSpace(command) == "" {
			return false
		}
		for _, l := range lines {
			if strings.Contains(l, command) {
				return true
			}
		}
		return false
	}
}
