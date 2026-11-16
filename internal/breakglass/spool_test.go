package breakglass

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSpool_Bounded(t *testing.T) {
	dir := t.TempDir()
	for i := range 70 {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.tok", i)), []byte(fmt.Sprintf("token-%02d", i)), 0o600)
	}
	os.WriteFile(filepath.Join(dir, "big.tok"), []byte(strings.Repeat("x", 1<<20)), 0o600)
	// A FIFO must not be opened (it would block).
	syscall.Mkfifo(filepath.Join(dir, "fifo.tok"), 0o600)
	got := ReadSpool(dir)
	if len(got) != 70 {
		t.Fatalf("read %d, want the 70 small files and no more", len(got))
	}
	for _, s := range got {
		if len(s) > 4096 {
			t.Fatal("large file read")
		}
	}
	if ReadSpool(filepath.Join(dir, "none")) != nil {
		t.Fatal("missing spool")
	}
}

// Anyone may create files here and set their times: junk must not hide a
// real token, however it is dated.
func TestSpool_CannotBeCrowdedOut(t *testing.T) {
	dir := t.TempDir()
	future := time.Now().Add(24 * time.Hour)
	for i := range 200 {
		p := filepath.Join(dir, fmt.Sprintf("junk-%03d.tok", i))
		os.WriteFile(p, []byte("junk"), 0o600)
		os.Chtimes(p, future, future)
	}
	real := filepath.Join(dir, "real.tok")
	os.WriteFile(real, []byte("the-real-token"), 0o600)
	os.Chtimes(real, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour))
	found := false
	for _, s := range ReadSpool(dir) {
		found = found || s == "the-real-token"
	}
	if !found {
		t.Fatal("the real token was hidden by 200 newer junk files")
	}
}

func TestSpoolFiles_NamesForPruning(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.tok"), []byte("tok-a\n7\n"), 0o600)
	fs := ReadSpoolFiles(dir)
	if len(fs) != 1 || fs[0].Name != "a.tok" || fs[0].Content != "tok-a\n7\n" {
		t.Fatalf("%+v", fs)
	}
}
