package baseline

import (
	"os"
	"testing"
)

// TestWriteEmptyEmbedded regenerates the placeholder embedded baseline.
// Run with XDR_GEN_EMBED=1; the real baseline is built from the clean image.
func TestWriteEmptyEmbedded(t *testing.T) {
	if os.Getenv("XDR_GEN_EMBED") == "" {
		t.Skip("set XDR_GEN_EMBED=1 to regenerate data/base.json.gz")
	}
	f, err := os.Create("data/base.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Save(f, &Baseline{Schema: 1, Files: map[string]FileEntry{}}); err != nil {
		t.Fatal(err)
	}
}
