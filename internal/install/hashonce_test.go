package install

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// Ensure reads (and hashes) each file once per call: the good-copy search
// and the manifest check share what was read.
func TestEnsure_ReadsEachFileOnce(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(l.p(l.Copies[0]), []byte("trojan"), 0o755)
	var mu sync.Mutex
	reads := map[string]int{}
	old := readFile
	readFile = func(p string) ([]byte, error) {
		mu.Lock()
		reads[p]++
		mu.Unlock()
		return old(p)
	}
	t.Cleanup(func() { readFile = old })
	rep, err := Ensure(l, (&fake{}).run)
	if err != nil || !contains(rep.Restored, l.Copies[0]) {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, c := range l.Copies {
		if reads[l.p(c)] != 1 {
			t.Errorf("%s read %d times", c, reads[l.p(c)])
		}
	}
	for p, n := range reads {
		if n > 1 {
			t.Errorf("%s read %d times", p, n)
		}
	}
}

func TestRender_GuardsLookEveryFiveSeconds(t *testing.T) {
	for _, f := range Render(DefaultLayout()) {
		if strings.Contains(f.Path, "xdr-guard-") && !strings.Contains(string(f.Content), " --every 5s") {
			t.Errorf("%s:\n%s", f.Path, f.Content)
		}
	}
}
