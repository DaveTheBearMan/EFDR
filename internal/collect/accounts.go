package collect

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math"
	"strings"

	"xdr/internal/baseline"
	"xdr/internal/pathenc"
)

// The account databases are parsed the way glibc's files backend parses
// them, because that is what login, sshd and sudo see: a line this parser
// rejected but glibc accepted would be an account the scan cannot see.

const blanks = " \t\n\v\f\r"

// eachLine calls fn for every line glibc would try to parse: leading
// blanks are dropped, empty lines and # comments skipped. Lines have no
// length limit.
func eachLine(r io.Reader, fn func(line string)) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		line = strings.TrimLeft(strings.TrimSuffix(line, "\n"), blanks)
		if line != "" && line[0] != '#' {
			fn(line)
		}
		if err != nil {
			return
		}
	}
}

// parseID reads a numeric id as strtoul does: leading blanks and a sign
// are accepted, and values past 32 bits saturate.
func parseID(s string) (uint32, bool) {
	s = strings.TrimLeft(s, blanks)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		d := uint64(s[i] - '0')
		if n > (math.MaxUint64-d)/10 {
			n, neg = math.MaxUint64, false
			continue
		}
		n = n*10 + d
	}
	if neg {
		n = -n
	}
	if n > math.MaxUint32 {
		n = math.MaxUint32
	}
	return uint32(n), true
}

// badLine keeps the start of a line no parser rule accepted, so that its
// appearance is still a visible change.
func badLine(line string) string {
	if len(line) > 80 {
		line = line[:80]
	}
	return pathenc.Encode(line)
}

func pwState(field string) (state, digest string) {
	switch {
	case field == "":
		state = "none"
	case strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*"):
		state = "locked"
	default:
		state = "set"
	}
	h := sha256.Sum256([]byte(field))
	return state, hex.EncodeToString(h[:])
}

// ParsePasswd parses /etc/passwd. The result is never nil. Lines that
// cannot be parsed are kept as Bad entries. Text fields are
// pathenc-encoded.
func ParsePasswd(r io.Reader) []baseline.Account {
	out := []baseline.Account{}
	eachLine(r, func(line string) {
		f := strings.SplitN(line, ":", 7)
		ok := len(f) >= 4 && f[0] != ""
		var uid, gid uint32
		if ok {
			uid, ok = parseID(f[2])
		}
		if ok {
			gid, ok = parseID(f[3])
		}
		if !ok {
			out = append(out, baseline.Account{Name: badLine(line), Bad: true})
			return
		}
		for len(f) < 7 {
			f = append(f, "")
		}
		a := baseline.Account{Name: pathenc.Encode(f[0]), UID: uid, GID: gid, Home: pathenc.Encode(f[5]), Shell: pathenc.Encode(f[6])}
		// Anything but "x" in the password field is the password itself.
		if f[1] != "x" {
			a.PwState, a.PwDigest = pwState(f[1])
		}
		out = append(out, a)
	})
	return out
}

// ApplyShadow fills password state from /etc/shadow for accounts whose
// passwd entry defers to it. The password field is stored only as a digest
// so password changes are detectable without retaining hashes.
func ApplyShadow(accts []baseline.Account, r io.Reader) {
	idx := map[string][]int{}
	for i, a := range accts {
		if !a.Bad && a.PwState == "" {
			idx[a.Name] = append(idx[a.Name], i)
		}
	}
	eachLine(r, func(line string) {
		f := strings.SplitN(line, ":", 3)
		if len(f) < 2 {
			return
		}
		name := pathenc.Encode(f[0])
		for _, i := range idx[name] {
			accts[i].PwState, accts[i].PwDigest = pwState(f[1])
		}
		delete(idx, name) // the first entry for a name is the one used
	})
}

// ParseGroup parses /etc/group. The result is never nil. Lines that cannot
// be parsed are kept as Bad entries. Names are pathenc-encoded.
func ParseGroup(r io.Reader) []baseline.Group {
	out := []baseline.Group{}
	eachLine(r, func(line string) {
		f := strings.SplitN(line, ":", 4)
		ok := len(f) >= 3 && f[0] != ""
		var gid uint32
		if ok {
			gid, ok = parseID(f[2])
		}
		if !ok {
			out = append(out, baseline.Group{Name: badLine(line), Bad: true})
			return
		}
		g := baseline.Group{Name: pathenc.Encode(f[0]), GID: gid}
		if len(f) == 4 {
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					g.Members = append(g.Members, pathenc.Encode(m))
				}
			}
		}
		out = append(out, g)
	})
	return out
}
