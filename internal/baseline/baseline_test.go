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
