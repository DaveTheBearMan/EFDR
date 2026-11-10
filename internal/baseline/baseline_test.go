package baseline

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"xdr/internal/pathenc"
)

func TestCodec_RoundTripOddPaths(t *testing.T) {
	key := pathenc.Encode("/tmp/\xff\n")
	b := &Baseline{
		Schema:     1,
		Host:       "h",
		CapturedAt: time.Now().UTC().Truncate(time.Second),
		Files:      map[string]FileEntry{key: {Type: TypeFile, Mode: 0644, SHA256: "ab", Content: []byte{0, 1, 2}}},
		Accounts:   []Account{{Name: "root", Shell: "/bin/bash"}},
		Modules:    []string{"bpf"},
	}
	var buf bytes.Buffer
	if err := Save(&buf, b); err != nil {
		t.Fatal(err)
	}
	got, err := Load(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, b) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, b)
	}
}

func TestCompose_LaterWins(t *testing.T) {
	base := &Baseline{Files: map[string]FileEntry{"/a": {SHA256: "1"}, "/b": {SHA256: "b"}}}
	over := &Baseline{Files: map[string]FileEntry{"/a": {SHA256: "2", Layer: LayerTriage}}}
	got := Compose(base, over)
	if got.Files["/a"].SHA256 != "2" || got.Files["/a"].Layer != LayerTriage {
		t.Fatalf("/a = %+v", got.Files["/a"])
	}
	if _, ok := got.Files["/b"]; !ok {
		t.Fatal("/b missing")
	}
	if base.Files["/a"].SHA256 != "1" {
		t.Fatal("Compose mutated its input")
	}
}

// A package-layer entry knows a file's content and packaged mode, nothing
// else. Laid over a full entry it must update those and keep the rest, or
// the package layer would erase what the base image knows.
func TestCompose_HashOnlyMergesIntoFullEntry(t *testing.T) {
	base := &Baseline{Files: map[string]FileEntry{
		"/usr/bin/x": {Type: TypeFile, Mode: 0o755, UID: 0, GID: 4, Caps: "01", SHA256: "1", Content: []byte("old")},
	}}
	pkg := &Baseline{Files: map[string]FileEntry{
		"/usr/bin/x": {Type: TypeFile, Mode: 0o700, SHA256: "2", HashOnly: true, Layer: LayerPackage},
	}}
	got := Compose(base, pkg).Files["/usr/bin/x"]
	want := FileEntry{Type: TypeFile, Mode: 0o700, UID: 0, GID: 4, Caps: "01", SHA256: "2", Layer: LayerPackage}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestCompose_HashOnlyDirNeverReplacesFullEntry(t *testing.T) {
	dir := FileEntry{Type: TypeDir, Mode: 0o755, UID: 0, GID: 0}
	base := &Baseline{Files: map[string]FileEntry{"/etc/cron.d": dir}}
	pkg := &Baseline{Files: map[string]FileEntry{
		"/etc/cron.d": {Type: TypeDir, Mode: 0o777, HashOnly: true, Layer: LayerPackage},
		"/etc/new.d":  {Type: TypeDir, Mode: 0o755, HashOnly: true, Layer: LayerPackage},
	}}
	got := Compose(base, pkg)
	if !reflect.DeepEqual(got.Files["/etc/cron.d"], dir) {
		t.Fatalf("got %+v", got.Files["/etc/cron.d"])
	}
	if !got.Files["/etc/new.d"].HashOnly {
		t.Fatal("a directory only the package ships is still added")
	}
}

func TestCompose_HashOnlyTypeChangeReplaces(t *testing.T) {
	base := &Baseline{Files: map[string]FileEntry{"/usr/bin/x": {Type: TypeFile, Mode: 0o755, SHA256: "1"}}}
	link := FileEntry{Type: TypeLink, Link: "y", HashOnly: true, Layer: LayerPackage}
	pkg := &Baseline{Files: map[string]FileEntry{"/usr/bin/x": link}}
	if got := Compose(base, pkg).Files["/usr/bin/x"]; !reflect.DeepEqual(got, link) {
		t.Fatalf("got %+v", got)
	}
}
