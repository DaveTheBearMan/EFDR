package debhash

import (
	"xdr/internal/baseline"
	"xdr/internal/pathenc"
)

// Layer builds a package-layer baseline from parsed packages. Entries are
// HashOnly: package metadata cannot predict ownership or modes changed by
// maintainer scripts, but content must match exactly.
func Layer(debs []*Deb) *baseline.Baseline {
	b := &baseline.Baseline{Schema: 1, Files: map[string]baseline.FileEntry{}}
	for _, d := range debs {
		for _, f := range d.Files {
			b.Files[pathenc.Encode(f.Path)] = baseline.FileEntry{
				Type: f.Type, Mode: f.Mode, SHA256: f.SHA256, Link: f.Link,
				HashOnly: true, Layer: baseline.LayerPackage,
			}
		}
	}
	return b
}
