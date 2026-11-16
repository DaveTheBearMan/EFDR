package breakglass

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpool_Bounded(t *testing.T) {
	dir := t.TempDir()
	old := time.Now().Add(-time.Hour)
	for i := range 70 {
		p := filepath.Join(dir, fmt.Sprintf("%02d.tok", i))
		os.WriteFile(p, []byte(fmt.Sprintf("token-%02d", i)), 0o600)
		os.Chtimes(p, old.Add(time.Duration(i)*time.Second), old.Add(time.Duration(i)*time.Second))
	}
	big := filepath.Join(dir, "big.tok")
	os.WriteFile(big, []byte(strings.Repeat("x", 1<<20)), 0o600)
	got := ReadSpool(dir)
	if len(got) > 64 {
		t.Fatalf("read %d", len(got))
	}
	for _, s := range got {
		if len(s) > 4096 {
			t.Fatal("large file read")
		}
	}
	if len(got) == 0 || got[0] != "token-69" {
		t.Fatalf("newest first: %v", got[:min(3, len(got))])
	}
	if ReadSpool(filepath.Join(dir, "none")) != nil {
		t.Fatal("missing spool")
	}
}
