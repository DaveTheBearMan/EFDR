package collect

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strconv"
	"strings"

	"xdr/internal/baseline"
)

func lines(r io.Reader, fields int, fn func(f []string)) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		f := strings.Split(s.Text(), ":")
		if len(f) == fields {
			fn(f)
		}
	}
}

func parseID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

// ParsePasswd parses /etc/passwd, skipping malformed lines.
func ParsePasswd(r io.Reader) []baseline.Account {
	var out []baseline.Account
	lines(r, 7, func(f []string) {
		uid, ok1 := parseID(f[2])
		gid, ok2 := parseID(f[3])
		if f[0] == "" || !ok1 || !ok2 {
			return
		}
		out = append(out, baseline.Account{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	})
	return out
}

// ApplyShadow fills password state from /etc/shadow. The password field is
// stored only as a digest so password changes are detectable without
// retaining hashes.
func ApplyShadow(accts []baseline.Account, r io.Reader) {
	idx := map[string]int{}
	for i, a := range accts {
		idx[a.Name] = i
	}
	lines(r, 9, func(f []string) {
		i, ok := idx[f[0]]
		if !ok {
			return
		}
		switch pw := f[1]; {
		case pw == "":
			accts[i].PwState = "none"
		case strings.HasPrefix(pw, "!") || strings.HasPrefix(pw, "*"):
			accts[i].PwState = "locked"
		default:
			accts[i].PwState = "set"
		}
		h := sha256.Sum256([]byte(f[1]))
		accts[i].PwDigest = hex.EncodeToString(h[:])
	})
}

// ParseGroup parses /etc/group, skipping malformed lines.
func ParseGroup(r io.Reader) []baseline.Group {
	var out []baseline.Group
	lines(r, 4, func(f []string) {
		gid, ok := parseID(f[2])
		if f[0] == "" || !ok {
			return
		}
		g := baseline.Group{Name: f[0], GID: gid}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	})
	return out
}
