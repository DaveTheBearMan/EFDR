package rules

import (
	"errors"
	"net/netip"
	"slices"

	"xdr/internal/baseline"
)

// Guard is what no rule may hit: the base image, the scored services and
// the addresses the fleet itself depends on.
type Guard struct {
	Baseline  func(sha256 string) bool // a hash of the base image
	GuardExes []string                 // scored-service binaries
	Protect   []netip.Prefix           // jump box, peers, resolver, scorer allows
}

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Validate reports why r may not be enforced, or nil.
func (g Guard) Validate(r Rule) error {
	switch r.Kind {
	case "hash":
		if !hexSum(r.SHA256) {
			return errors.New("bad hash")
		}
		if g.Baseline != nil && g.Baseline(r.SHA256) {
			return errors.New("baseline hash")
		}
		if slices.Contains(g.GuardExes, r.Exe) {
			return errors.New("guarded exe")
		}
	case "remote":
		a := r.Addr.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
			a.IsLinkLocalUnicast() || a.IsInterfaceLocalMulticast() || a == broadcast {
			return errors.New("not a unicast address")
		}
		if r.Port == 0 {
			return errors.New("no port")
		}
		if r.Proto != "tcp" && r.Proto != "udp" {
			return errors.New("bad proto")
		}
		for _, p := range g.Protect {
			if p.Contains(a) {
				return errors.New("protected address")
			}
		}
	default:
		return errors.New("unknown kind")
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

// BaselineHashes is the set of file hashes in b.
func BaselineHashes(b *baseline.Baseline) func(string) bool {
	set := map[string]bool{}
	if b != nil {
		for _, e := range b.Files {
			if e.SHA256 != "" {
				set[e.SHA256] = true
			}
		}
	}
	return func(s string) bool { return set[s] }
}
