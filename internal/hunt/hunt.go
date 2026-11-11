// Package hunt carries what one box found to every other: the indicators
// an incident left, and the search for them. Searching is harmless, so a
// hunt may come from any peer; it is bounded, and trusted for nothing else.
package hunt

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"xdr/internal/incident"
	"xdr/internal/rules"
)

// Remote is an endpoint a process talked to.
type Remote struct {
	Addr  netip.Addr `json:"addr"`
	Port  uint16     `json:"port"`
	Proto string     `json:"proto"`
}

// File is a binary by hash and size. A file found at Path with another
// hash is a variant.
type File struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path,omitempty"`
}

// IOC is the indicator set a hunt searches for.
type IOC struct {
	Files   []File   `json:"files,omitempty"`
	Remotes []Remote `json:"remotes,omitempty"`
	Units   []string `json:"units,omitempty"` // unit names, with their file hash after "@"
	Cron    []string `json:"cron,omitempty"`
	Users   []string `json:"users,omitempty"`
}

func (i IOC) empty() bool {
	return len(i.Files)+len(i.Remotes)+len(i.Units)+len(i.Cron)+len(i.Users) == 0
}

// Request is one hunt.
type Request struct {
	ID   string    `json:"id"`
	From string    `json:"from"`
	Time time.Time `json:"time"`
	IOC  IOC       `json:"ioc"`
}

const (
	maxList = 64
	maxStr  = 512
)

// ID names an indicator set: the same indicators found twice are one hunt.
func ID(ioc IOC) string {
	c := IOC{
		Files:   slices.Clone(ioc.Files),
		Remotes: slices.Clone(ioc.Remotes),
		Units:   slices.Sorted(slices.Values(ioc.Units)),
		Cron:    slices.Sorted(slices.Values(ioc.Cron)),
		Users:   slices.Sorted(slices.Values(ioc.Users)),
	}
	slices.SortFunc(c.Files, func(a, b File) int {
		return cmp.Or(strings.Compare(a.SHA256, b.SHA256), strings.Compare(a.Path, b.Path), cmp.Compare(a.Size, b.Size))
	})
	slices.SortFunc(c.Remotes, func(a, b Remote) int {
		return cmp.Or(a.Addr.Compare(b.Addr), cmp.Compare(a.Port, b.Port), strings.Compare(a.Proto, b.Proto))
	})
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func strs(field string, l []string) error {
	if len(l) > maxList {
		return fmt.Errorf("%s: %d entries", field, len(l))
	}
	for _, s := range l {
		if s == "" || len(s) > maxStr {
			return fmt.Errorf("%s: entry of %d bytes", field, len(s))
		}
	}
	return nil
}

// Bound refuses a request that is too big, malformed, or whose ID is not
// its indicators'. The error names the field.
func (r *Request) Bound() error {
	if len(r.From) > maxStr {
		return fmt.Errorf("from: %d bytes", len(r.From))
	}
	i := r.IOC
	if len(i.Files) > maxList {
		return fmt.Errorf("files: %d entries", len(i.Files))
	}
	for _, f := range i.Files {
		if !hexSum(f.SHA256) || f.Size < 0 || len(f.Path) > maxStr {
			return fmt.Errorf("files: bad entry %.80q", f.Path)
		}
	}
	if len(i.Remotes) > maxList {
		return fmt.Errorf("remotes: %d entries", len(i.Remotes))
	}
	for _, e := range i.Remotes {
		if !e.Addr.IsValid() || e.Port == 0 || e.Proto != "tcp" && e.Proto != "udp" {
			return fmt.Errorf("remotes: bad entry %v/%s", netip.AddrPortFrom(e.Addr, e.Port), e.Proto)
		}
	}
	for _, f := range []struct {
		name string
		l    []string
	}{{"units", i.Units}, {"cron", i.Cron}, {"users", i.Users}} {
		if err := strs(f.name, f.l); err != nil {
			return err
		}
	}
	if r.ID != ID(i) {
		return fmt.Errorf("id %.32q does not match the indicators", r.ID)
	}
	return nil
}

func hexSum(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Base says what is the base image's: a binary at a path with a hash, and
// an account.
type Base struct {
	Exe  func(path, sha string) bool
	User func(name string) bool
}

// FromIncident is the hunt an incident starts, or nil: only incidents
// that propose rules start one, and only for indicators the base image
// does not share.
func FromIncident(in incident.Incident, base Base) *Request {
	if !rules.Proposes(in) {
		return nil
	}
	var ioc IOC
	if in.SHA256 != "" && (base.Exe == nil || !base.Exe(in.Exe, in.SHA256)) {
		ioc.Files = append(ioc.Files, File{SHA256: in.SHA256, Size: in.Size, Path: in.Exe})
	}
	if e := in.Remote; e != nil && e.Port != 0 && (e.Proto == "tcp" || e.Proto == "udp") {
		if a, err := netip.ParseAddr(e.Addr); err == nil {
			ioc.Remotes = append(ioc.Remotes, Remote{Addr: a.Unmap(), Port: e.Port, Proto: e.Proto})
		}
	}
	if u, ok := strings.CutPrefix(in.Origin, "unit:"); ok && in.OriginSHA256 != "" {
		ioc.Units = append(ioc.Units, u+"@"+in.OriginSHA256)
	}
	if in.Cron != "" {
		ioc.Cron = append(ioc.Cron, in.Cron)
	}
	if in.User != "" && (base.User == nil || !base.User(in.User)) {
		ioc.Users = append(ioc.Users, in.User)
	}
	if ioc.empty() {
		return nil
	}
	return &Request{ID: ID(ioc), From: in.Host, Time: in.Time, IOC: ioc}
}
