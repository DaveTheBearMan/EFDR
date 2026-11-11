package collect

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/testfs"
)

func TestWalk_HashIsBounded(t *testing.T) {
	old := maxHash
	maxHash = 8
	defer func() { maxHash = old }()
	root := testfs.Root(t)
	testfs.File(t, root, "srv/big", "0123456789abcdef", 0o644)
	testfs.File(t, root, "srv/small", "01234567", 0o644)
	files, _ := Walk(root)
	if e := files["/srv/big"]; e.SHA256 != "partial:"+sum("01234567") || e.Size != 16 || e.Err != "" {
		t.Errorf("big %+v", e)
	}
	if e := files["/srv/small"]; e.SHA256 != sum("01234567") {
		t.Errorf("small %+v", e)
	}
}

func TestDigest_ContentDroppedWhenFileGrew(t *testing.T) {
	in := strings.Repeat("a", maxContent+10)
	sha, content, err := digest(strings.NewReader(in), true)
	if err != nil || sha != sum(in) || content != nil {
		t.Fatalf("sha=%s content=%d bytes err=%v", sha, len(content), err)
	}
}

func TestPseudoFS(t *testing.T) {
	if !PseudoFS("/proc") || !PseudoFS("/sys") {
		t.Error("/proc and /sys must be recognised wherever they are mounted")
	}
	if PseudoFS(t.TempDir()) {
		t.Error("an ordinary directory is not a kernel filesystem")
	}
}

// Between lstat and open a path can be swapped for a fifo. The open must
// not block and the swap must surface as an error, not as an empty file.
func TestHashFile_RefusesFifoWithoutBlocking(t *testing.T) {
	root := testfs.Root(t)
	testfs.Fifo(t, root, "srv/pipe")
	done := make(chan error, 1)
	go func() {
		_, _, err := hashFile(filepath.Join(root, "srv/pipe"), true)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a fifo was hashed as if it were a file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hashFile blocked on a fifo")
	}
}
