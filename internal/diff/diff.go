// Package diff compares a live snapshot against a baseline.
package diff

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pmezard/go-difflib/difflib"

	"xdr/internal/baseline"
	"xdr/internal/classify"
	"xdr/internal/model"
	"xdr/internal/pathenc"
)

// Diff returns every difference between base and live, most severe first.
func Diff(base, live *baseline.Baseline) []model.Finding {
	out := diffFiles(base.Files, live.Files)
	out = append(out, collectorErrors(live.Errors)...)
	groups := live.Groups
	if groups == nil {
		groups = base.Groups
	}
	out = append(out, diffAccounts(base.Accounts, live.Accounts, privilegedGIDs(groups))...)
	out = append(out, diffGroups(base.Groups, live.Groups)...)
	out = append(out, diffModules(base.Modules, live.Modules)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func diffFiles(base, live map[string]baseline.FileEntry) []model.Finding {
	var out []model.Finding
	for key, l := range live {
		b, ok := base[key]
		if b.Err != "" {
			ok = false // an entry the baseline could not read vouches for nothing
		}
		cls := classOf(key)
		switch {
		case l.Err != "":
			// What could not be read could not be compared.
			f := model.Finding{Kind: model.KindError, Category: cls.Category, Severity: max(cls.Severity, model.SevHigh),
				Subject: key, Detail: "could not read: " + l.Err}
			if ok {
				f.Before = ident(b)
			}
			out = append(out, f)
		case !ok:
			f := model.Finding{Kind: model.KindAdded, Category: cls.Category, Severity: cls.Severity,
				Subject: key, Detail: "new " + typeName(l.Type), After: ident(l)}
			if privileged(l) {
				f.Category, f.Severity = "privilege", model.SevCritical
				f.Detail += ", " + privDetail(l)
			}
			out = append(out, f)
		default:
			changed := changes(b, l)
			if len(changed) == 0 {
				continue
			}
			f := model.Finding{Kind: model.KindAltered, Category: cls.Category, Severity: cls.Severity,
				Subject: key, Detail: strings.Join(changed, ", "), Before: ident(b), After: ident(l)}
			if gainedPriv(b, l) {
				f.Category, f.Severity = "privilege", model.SevCritical
			}
			// A directory swapped for anything else redirects all it held.
			if b.Type == baseline.TypeDir && l.Type != baseline.TypeDir {
				f.Severity = max(f.Severity, model.SevHigh)
			}
			if b.Content != nil && l.Content != nil {
				f.Diff = unified(b.Content, l.Content)
			}
			out = append(out, f)
		}
	}
	for key, b := range base {
		if _, ok := live[key]; ok {
			continue
		}
		cls := classOf(key)
		sev := cls.Severity - 1
		if cls.Category == "system-binary" || cls.Category == "file" {
			sev = model.SevMedium
		}
		out = append(out, model.Finding{Kind: model.KindRemoved, Category: cls.Category, Severity: sev,
			Subject: key, Detail: typeName(b.Type) + " removed", Before: ident(b)})
	}
	return out
}

// collectorErrors reports the files a snapshot reads by name (passwd,
// group, ...) that it could not read safely.
func collectorErrors(errs []string) []model.Finding {
	var out []model.Finding
	for _, e := range errs {
		subject, why, ok := strings.Cut(e, ": ")
		if !ok {
			subject, why = "snapshot", e
		}
		out = append(out, model.Finding{Kind: model.KindError, Category: "collector", Severity: model.SevHigh,
			Subject: subject, Detail: "could not read: " + why})
	}
	return out
}

func classOf(key string) classify.Class {
	p, err := pathenc.Decode(key)
	if err != nil {
		p = key
	}
	return classify.Path(p)
}

// changes lists the compared fields that differ, described for humans.
func changes(b, l baseline.FileEntry) []string {
	var c []string
	if b.Type != l.Type {
		c = append(c, fmt.Sprintf("type %s→%s", typeName(b.Type), typeName(l.Type)))
	}
	if b.SHA256 != l.SHA256 {
		c = append(c, "sha256")
	} else if strings.HasPrefix(l.SHA256, "partial:") && b.Size != l.Size {
		// Only the head of a very large file is hashed.
		c = append(c, fmt.Sprintf("size %d→%d", b.Size, l.Size))
	}
	if b.Link != l.Link {
		c = append(c, fmt.Sprintf("link %s→%s", b.Link, l.Link))
	}
	if b.HashOnly {
		// A package vouches for content and packaged mode only, but never
		// for privilege it did not ship.
		if g := gained(b, l); privileged(g) {
			c = append(c, "gained "+privDetail(g))
		}
		return c
	}
	if b.Caps != l.Caps {
		c = append(c, "caps")
	}
	if b.Mode != l.Mode {
		c = append(c, fmt.Sprintf("mode %s→%s", octal(b.Mode), octal(l.Mode)))
	}
	if b.UID != l.UID || b.GID != l.GID {
		c = append(c, fmt.Sprintf("owner %d:%d→%d:%d", b.UID, b.GID, l.UID, l.GID))
	}
	return c
}

const privBits = uint32(os.ModeSetuid | os.ModeSetgid)

func privileged(e baseline.FileEntry) bool { return e.Mode&privBits != 0 || e.Caps != "" }

func gainedPriv(b, l baseline.FileEntry) bool { return privileged(gained(b, l)) }

// gained returns l reduced to the setuid/setgid bits and capabilities it
// has beyond b.
func gained(b, l baseline.FileEntry) baseline.FileEntry {
	g := baseline.FileEntry{}
	if b.HashOnly && l.Type != baseline.TypeFile {
		return g // packages do not record what their scripts chmod on directories
	}
	g.Mode = l.Mode & privBits &^ b.Mode
	if l.Caps != b.Caps {
		g.Caps = l.Caps
	}
	return g
}

func privDetail(e baseline.FileEntry) string {
	var p []string
	if e.Mode&uint32(os.ModeSetuid) != 0 {
		p = append(p, "setuid")
	}
	if e.Mode&uint32(os.ModeSetgid) != 0 {
		p = append(p, "setgid")
	}
	if e.Caps != "" {
		p = append(p, "caps")
	}
	return strings.Join(p, "+")
}

// octal renders a Go file mode in chmod notation, e.g. 4755.
func octal(m uint32) string {
	fm := os.FileMode(m)
	n := uint32(fm.Perm())
	if fm&os.ModeSetuid != 0 {
		n |= 0o4000
	}
	if fm&os.ModeSetgid != 0 {
		n |= 0o2000
	}
	if fm&os.ModeSticky != 0 {
		n |= 0o1000
	}
	return fmt.Sprintf("%04o", n)
}

func typeName(t baseline.FileType) string {
	switch t {
	case baseline.TypeFile:
		return "file"
	case baseline.TypeDir:
		return "dir"
	case baseline.TypeLink:
		return "symlink"
	default:
		return "special file"
	}
}

func ident(e baseline.FileEntry) string {
	if e.Type == baseline.TypeLink {
		return e.Link
	}
	return e.SHA256
}

// lines splits content keeping line endings. Unlike difflib.SplitLines it
// does not invent an extra empty line after a trailing newline.
func lines(b []byte) []string {
	ls := strings.SplitAfter(string(b), "\n")
	if ls[len(ls)-1] == "" {
		ls = ls[:len(ls)-1]
	} else {
		ls[len(ls)-1] += "\n"
	}
	return ls
}

func unified(a, b []byte) string {
	s, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: lines(a), B: lines(b),
		FromFile: "baseline", ToFile: "live", Context: 3,
	})
	return s
}
