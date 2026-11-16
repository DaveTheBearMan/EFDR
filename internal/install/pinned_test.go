package install

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// With the install's units there, a missing pinned hash (both copies) is
// not "not installed": ensure says so, and leaves a note for the agent.
func TestEnsure_PinnedGoneWithUnitsIsReported(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	os.Remove(l.p(l.Pinned))
	os.Remove(l.p(l.Backup + "/pinned.sha256"))
	_, err := Ensure(l, (&fake{}).run)
	if err == nil || errors.Is(err, ErrNotInstalled) || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("%v", err)
	}
	if n := TakeNotes(l); len(n) != 1 || n[0].Error == "" {
		t.Fatalf("notes %+v", n)
	}
}

// One pinned copy gone: put back from the other, as before.
func TestEnsure_PinnedRestoredFromBackup(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	os.Remove(l.p(l.Pinned))
	rep, err := Ensure(l, (&fake{}).run)
	if err != nil || !contains(rep.Restored, l.Pinned) {
		t.Fatalf("%+v %v", rep, err)
	}
}

// Uninstall writes the marker before anything else; with it there ensure
// stands down even while files remain; Install takes it away.
func TestUninstall_MarkerDecidesUninstalled(t *testing.T) {
	l := testLayout(t)
	bin := binary(t, "#!/bin/sh\necho agent\n")
	if _, err := Install(l, (&fake{}).run, bin); err != nil {
		t.Fatal(err)
	}
	if Uninstalled(l) {
		t.Fatal("marked uninstalled after an install")
	}
	marked := map[string]bool{}
	f := &fake{}
	run := func(name string, args ...string) ([]byte, error) {
		marked[name+" "+strings.Join(args, " ")] = Uninstalled(l)
		return f.run(name, args...)
	}
	if err := Uninstall(l, run); err != nil {
		t.Fatal(err)
	}
	for c, m := range marked {
		if !m {
			t.Errorf("%q ran before the marker was written", c)
		}
	}
	if !Uninstalled(l) {
		t.Fatal("no marker after the uninstall")
	}
	// Files put back by hand: the marker still says uninstalled.
	write(t, l.p("/etc/systemd/system/xdr-agent.service"), "x", 0o644)
	if _, err := Ensure(l, (&fake{}).run); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("%v", err)
	}
	write(t, l.p(l.Config), "{\"host\":\"web01\"}\n", 0o600)
	if _, err := Install(l, (&fake{}).run, bin); err != nil {
		t.Fatal(err)
	}
	if Uninstalled(l) {
		t.Fatal("the install left the marker")
	}
	if _, err := Ensure(l, (&fake{}).run); err != nil {
		t.Fatal(err)
	}
}

// Repin rewrites missing pinned files from the given hash and a missing
// manifest from the one given (or rebuilt), and says what it wrote.
func TestRepin_RewritesBothPinnedFiles(t *testing.T) {
	l := testLayout(t)
	bin := binary(t, "#!/bin/sh\necho agent\n")
	if _, err := Install(l, (&fake{}).run, bin); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(bin)
	want, _ := os.ReadFile(l.p(l.Manifest))
	for _, p := range []string{l.Pinned, l.Backup + "/pinned.sha256", l.Manifest, l.Backup + "/manifest.json"} {
		os.Remove(l.p(p))
	}
	f := &fake{}
	wrote, err := Repin(l, f.run, sum(b), nil)
	if err != nil || len(wrote) != 4 {
		t.Fatalf("%v %v", wrote, err)
	}
	if got, _ := os.ReadFile(l.p(l.Pinned)); strings.TrimSpace(string(got)) != sum(b) {
		t.Fatalf("pinned %q", got)
	}
	if got, _ := os.ReadFile(l.p(l.Manifest)); string(got) != string(want) {
		t.Fatalf("manifest rebuilt differently:\n%s\n%s", got, want)
	}
	if f.count("chattr +i") < 4 {
		t.Fatalf("not made immutable: %v", f.cmds)
	}
	if _, err := Ensure(l, (&fake{}).run); err != nil {
		t.Fatal(err)
	}
	// Nothing missing: nothing written.
	if wrote, err := Repin(l, f.run, sum(b), nil); err != nil || len(wrote) != 0 {
		t.Fatalf("%v %v", wrote, err)
	}
	// Uninstalled: never.
	os.Remove(l.p(l.Pinned))
	write(t, l.p(l.Uninstalled), "", 0o600)
	if wrote, _ := Repin(l, f.run, sum(b), nil); len(wrote) != 0 {
		t.Fatalf("repinned an uninstalled box: %v", wrote)
	}
}
