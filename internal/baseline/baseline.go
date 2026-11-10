// Package baseline defines a host snapshot and how snapshots compose.
//
// All paths stored in a Baseline are pathenc-encoded absolute paths as seen
// from the captured root (e.g. "/etc/crontab").
package baseline

import "time"

// Layer records where a known-good entry came from.
type Layer uint8

const (
	LayerBase    Layer = iota // clean base image, embedded in the binary
	LayerPackage              // scored-service packages, hashed off-box from .debs
	LayerTriage               // competition-specific state approved at T-0
)

// FileType is the kind of filesystem object.
type FileType byte

const (
	TypeFile  FileType = 'f'
	TypeDir   FileType = 'd'
	TypeLink  FileType = 'l'
	TypeOther FileType = 'o' // fifo, socket, device
)

// FileEntry describes one filesystem object.
type FileEntry struct {
	Type     FileType
	Mode     uint32 // os.FileMode bits, including setuid/setgid
	UID, GID uint32
	Size     int64
	SHA256   string
	Link     string
	Caps     string // hex of the security.capability xattr, "" if none
	Content  []byte // kept only for small persistence-relevant files
	HashOnly bool   // compare only Type/SHA256/Link (package layer)
	Layer    Layer
	Err      string // read error, if any
}

// Account is one /etc/passwd entry joined with its shadow state.
type Account struct {
	Name     string
	UID, GID uint32
	Home     string
	Shell    string
	PwState  string // "locked", "none" or "set"
	PwDigest string // sha256 of the shadow password field
}

// Group is one /etc/group entry.
type Group struct {
	Name    string
	GID     uint32
	Members []string
}

// Baseline is a complete host snapshot.
type Baseline struct {
	Schema     int
	Host       string
	OSRelease  string
	CapturedAt time.Time
	Files      map[string]FileEntry
	Accounts   []Account
	Groups     []Group
	Modules    []string // nil means not captured (offline image)
	Errors     []string
}

// Compose overlays layers in order: a later layer's entry wins per path, and
// the last non-nil Accounts, Groups and Modules win. Inputs are not modified.
func Compose(layers ...*Baseline) *Baseline {
	out := &Baseline{Schema: 1, Files: map[string]FileEntry{}}
	for _, l := range layers {
		if l == nil {
			continue
		}
		if l.Host != "" {
			out.Host = l.Host
		}
		if l.OSRelease != "" {
			out.OSRelease = l.OSRelease
		}
		if l.CapturedAt.After(out.CapturedAt) {
			out.CapturedAt = l.CapturedAt
		}
		for p, e := range l.Files {
			out.Files[p] = e
		}
		if l.Accounts != nil {
			out.Accounts = l.Accounts
		}
		if l.Groups != nil {
			out.Groups = l.Groups
		}
		if l.Modules != nil {
			out.Modules = l.Modules
		}
	}
	return out
}
