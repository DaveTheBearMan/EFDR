package debhash

import (
	"bufio"
	"io"
	"strings"
)

// Installed is one installed package from the dpkg status database.
type Installed struct {
	Package, Version, Arch string
}

// ParseStatus parses /var/lib/dpkg/status, returning only packages whose
// status is "install ok installed". It is used to learn which versions to
// verify; it is never a source of trusted hashes.
func ParseStatus(r io.Reader) []Installed {
	var out []Installed
	var cur Installed
	var installed bool
	flush := func() {
		if installed && cur.Package != "" {
			out = append(out, cur)
		}
		cur, installed = Installed{}, false
	}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // continuation line
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			cur.Package = v
		case "Version":
			cur.Version = v
		case "Architecture":
			cur.Arch = v
		case "Status":
			installed = v == "install ok installed"
		}
	}
	flush()
	return out
}
