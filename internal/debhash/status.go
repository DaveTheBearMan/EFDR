package debhash

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

// Debian's grammar for the fields that reach stdout and apt (policy 5.6.1,
// 5.6.12); an entry outside it is dropped.
var (
	pkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	pkgVer  = regexp.MustCompile(`^[0-9A-Za-z.+~:-]+$`)
	pkgArch = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// Installed is one installed package from the dpkg status database.
type Installed struct {
	Package, Version, Arch string
}

// ParseStatus parses /var/lib/dpkg/status, returning only packages whose
// status is "install ok installed". It is used to learn which versions to
// verify; it is never a source of trusted hashes. A line over the scanner's
// limit is an error, so a list is never silently cut short.
func ParseStatus(r io.Reader) ([]Installed, error) {
	var out []Installed
	var cur Installed
	var installed bool
	flush := func() {
		if installed && pkgName.MatchString(cur.Package) && pkgVer.MatchString(cur.Version) && pkgArch.MatchString(cur.Arch) {
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
	return out, s.Err()
}
