package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fake is a Runner that records every command and answers is-active from a map.
type fake struct {
	mu     sync.Mutex
	cmds   []string
	active map[string]string // unit → what `systemctl is-active` prints
	fail   map[string]error  // command prefix → error
}

func (f *fake) run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, cmd)
	for prefix, err := range f.fail {
		if strings.HasPrefix(cmd, prefix) {
			return nil, err
		}
	}
	if name == "systemctl" && len(args) == 2 && args[0] == "is-active" {
		if s, ok := f.active[args[1]]; ok {
			return []byte(s + "\n"), nil
		}
		return []byte("active\n"), nil
	}
	return nil, nil
}

func (f *fake) count(prefix string) int {
	n := 0
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func testLayout(t *testing.T) Layout {
	root := t.TempDir()
	l := DefaultLayout()
	l.Root = root
	// The config and bundle to be backed up.
	write(t, l.p(l.Config), "{\"host\":\"web01\"}\n", 0o600)
	write(t, l.p(l.Config+".sig"), "c2ln\n", 0o644)
	write(t, l.p(l.FleetDir+"/ca.pem"), "CA\n", 0o600)
	write(t, l.p(l.FleetDir+"/host.pem"), "HOST\n", 0o600)
	return l
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func binary(t *testing.T, content string) string {
	p := filepath.Join(t.TempDir(), "xdr-new")
	write(t, p, content, 0o755)
	return p
}

func TestChooser_PicksTheGoodCopy(t *testing.T) {
	l := DefaultLayout()
	l.Root = t.TempDir()
	good := "#!/bin/sh\necho ran \"$@\"\n"
	for i, c := range l.Copies {
		content := good
		if i != 1 {
			content = "#!/bin/sh\necho CORRUPT\n"
		}
		write(t, l.p(c), content, 0o755)
	}
	write(t, l.p(l.Pinned), sum([]byte(good))+"\n", 0o644)
	out, err := exec.Command("/bin/sh", "-c", Chooser(l), "xdr", "agent", "--x").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ran agent --x" {
		t.Fatalf("%q %v", out, err)
	}
	write(t, l.p(l.Pinned), strings.Repeat("0", 64)+"\n", 0o644)
	err = exec.Command("/bin/sh", "-c", Chooser(l), "xdr", "ensure").Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 127 {
		t.Fatalf("with no good copy: %v", err)
	}
}

func TestRender_LaunchPoints(t *testing.T) {
	l := DefaultLayout()
	files := map[string]string{}
	for _, f := range Render(l) {
		files[f.Path] = string(f.Content)
	}
	want := map[string]string{
		"/etc/systemd/system/xdr-agent.service":            "agent",
		"/etc/systemd/system/xdr-guard-a.service":          "guard --watch xdr-guard-b.service",
		"/etc/systemd/system/xdr-guard-b.service":          "guard --watch xdr-guard-a.service",
		"/etc/systemd/system/xdr-ensure.service":           "ensure",
		"/etc/cron.d/xdr-ensure":                           "ensure",
		"/usr/lib/systemd/system-generators/xdr-generator": "xdr-agent.service",
		"/usr/lib/xdr/launch":                              "exit 127",
	}
	for path, frag := range want {
		c, ok := files[path]
		if !ok || !strings.Contains(c, frag) {
			t.Errorf("%s: missing or lacks %q:\n%s", path, frag, c)
		}
	}
	for _, p := range []string{"/etc/systemd/system/xdr-agent.service", "/etc/systemd/system/xdr-guard-a.service", "/etc/systemd/system/xdr-ensure.service", "/etc/cron.d/xdr-ensure"} {
		if !strings.Contains(files[p], "sha256sum") || !strings.Contains(files[p], l.Pinned) {
			t.Errorf("%s does not pick a copy by the pinned hash", p)
		}
	}
	if !strings.Contains(files["/etc/systemd/system/xdr-agent.service"], "Restart=always") || !strings.Contains(files["/etc/systemd/system/xdr-guard-a.service"], "Restart=always") {
		t.Error("a service that does not restart")
	}
	if !strings.Contains(files["/etc/systemd/system/xdr-ensure.timer"], "OnUnitActiveSec=30s") {
		t.Errorf("timer:\n%s", files["/etc/systemd/system/xdr-ensure.timer"])
	}
	cron := files["/etc/cron.d/xdr-ensure"]
	if !strings.Contains(cron, "@reboot root") || !strings.Contains(cron, "* * * * * root") {
		t.Errorf("cron:\n%s", cron)
	}
	if !strings.Contains(files["/etc/apt/apt.conf.d/99xdr"], "DPkg::Post-Invoke") || !strings.Contains(files["/etc/apt/apt.conf.d/99xdr"], "/usr/lib/xdr/launch ensure") {
		t.Errorf("apt hook:\n%s", files["/etc/apt/apt.conf.d/99xdr"])
	}
	// systemd treats $ and % in a unit specially.
	for _, p := range []string{"/etc/systemd/system/xdr-agent.service", "/etc/systemd/system/xdr-guard-a.service"} {
		for _, line := range strings.Split(files[p], "\n") {
			if strings.HasPrefix(line, "ExecStart=") && strings.Contains(strings.ReplaceAll(line, "$$", ""), "$") {
				t.Errorf("%s: an unescaped $: %s", p, line)
			}
		}
	}
}

func TestInstall_WritesEverythingOnceAndIsIdempotent(t *testing.T) {
	l := testLayout(t)
	f := &fake{}
	bin := binary(t, "#!/bin/sh\necho agent\n")
	rep, err := Install(l, f.run, bin)
	if err != nil || len(rep.Wrote) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	want, _ := os.ReadFile(bin)
	for _, c := range l.Copies {
		got, err := os.ReadFile(l.p(c))
		if err != nil || string(got) != string(want) {
			t.Fatalf("copy %s: %v", c, err)
		}
		if st, _ := os.Stat(l.p(c)); st.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode %v", c, st.Mode())
		}
	}
	if p, _ := os.ReadFile(l.p(l.Pinned)); strings.TrimSpace(string(p)) != sum(want) {
		t.Fatalf("pinned %q", p)
	}
	m, err := ReadManifest(l)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, e := range m.Entries {
		paths[e.Path] = true
	}
	for _, p := range append(append([]string{}, l.Copies...), "/etc/systemd/system/xdr-agent.service", "/etc/cron.d/xdr-ensure", l.Backup+"/agent.json", l.Backup+"/fleet/ca.pem") {
		if !paths[p] {
			t.Errorf("the manifest lacks %s", p)
		}
	}
	if f.count("chattr +i") == 0 || f.count("systemctl daemon-reload") != 1 || f.count("systemctl enable --now xdr-agent.service") != 1 {
		t.Fatalf("commands: %v", f.cmds)
	}
	g := &fake{}
	rep, err = Install(l, g.run, bin)
	if err != nil || len(rep.Wrote) != 0 {
		t.Fatalf("second install wrote %v (%v)", rep.Wrote, err)
	}
	if g.count("systemctl enable") != 0 || g.count("systemctl daemon-reload") != 0 {
		t.Fatalf("second install: %v", g.cmds)
	}
}

func TestInstall_FailureKeepsTheOldInstall(t *testing.T) {
	l := testLayout(t)
	old := binary(t, "#!/bin/sh\necho old\n")
	if _, err := Install(l, (&fake{}).run, old); err != nil {
		t.Fatal(err)
	}
	// The third copy's directory becomes a file: its write fails.
	third := filepath.Dir(l.p(l.Copies[2]))
	os.RemoveAll(third)
	os.WriteFile(third, []byte("in the way"), 0o644)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho new\n")); err == nil {
		t.Fatal("an install that could not write a copy succeeded")
	}
	for _, c := range l.Copies[:2] {
		if b, _ := os.ReadFile(l.p(c)); !strings.Contains(string(b), "old") {
			t.Fatalf("%s was replaced by a failed install: %q", c, b)
		}
	}
	if p, _ := os.ReadFile(l.p(l.Pinned)); strings.TrimSpace(string(p)) == sum([]byte("#!/bin/sh\necho new\n")) {
		t.Fatal("the pinned hash moved to the new binary")
	}
}

func TestEnsure_RestoresAndStarts(t *testing.T) {
	l := testLayout(t)
	f := &fake{}
	bin := binary(t, "#!/bin/sh\necho agent\n")
	if _, err := Install(l, f.run, bin); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(bin)
	// A quiet box: nothing to do.
	g := &fake{}
	rep, err := Ensure(l, g.run)
	if err != nil || len(rep.Restored) != 0 || len(rep.Started) != 0 {
		t.Fatalf("a good box: %+v %v", rep, err)
	}
	// Attacks: a copy overwritten, a unit and a backup file deleted, the agent stopped.
	os.WriteFile(l.p(l.Copies[0]), []byte("trojan"), 0o755)
	os.Remove(l.p("/etc/systemd/system/xdr-guard-a.service"))
	os.Remove(l.p(l.Backup + "/agent.json.sig"))
	os.Remove(l.p(l.Config))
	h := &fake{active: map[string]string{"xdr-agent.service": "inactive", "xdr-guard-b.service": "failed"}}
	rep, err = Ensure(l, h.run)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{l.Copies[0], "/etc/systemd/system/xdr-guard-a.service", l.Backup + "/agent.json.sig", l.Config} {
		if !contains(rep.Restored, p) {
			t.Errorf("not restored: %s (%v)", p, rep.Restored)
		}
	}
	if got, _ := os.ReadFile(l.p(l.Copies[0])); string(got) != string(want) {
		t.Fatalf("the copy: %q", got)
	}
	if got, _ := os.ReadFile(l.p("/etc/systemd/system/xdr-guard-a.service")); !strings.Contains(string(got), "guard --watch xdr-guard-b.service") {
		t.Fatalf("the unit: %q", got)
	}
	if got, _ := os.ReadFile(l.p(l.Config)); string(got) != "{\"host\":\"web01\"}\n" {
		t.Fatalf("the config: %q", got)
	}
	if !contains(rep.Started, "xdr-agent.service") || !contains(rep.Started, "xdr-guard-b.service") || h.count("systemctl start xdr-agent.service") != 1 || h.count("systemctl daemon-reload") != 1 {
		t.Fatalf("started %v: %v", rep.Started, h.cmds)
	}
	if h.count("chattr -i") == 0 || h.count("chattr +i") == 0 {
		t.Fatalf("immutability not handled: %v", h.cmds)
	}
}

func TestEnsure_NoGoodCopy(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	for _, c := range l.Copies {
		os.WriteFile(l.p(c), []byte("trojan"), 0o755)
	}
	os.Remove(l.p("/etc/systemd/system/xdr-guard-a.service"))
	f := &fake{}
	rep, err := Ensure(l, f.run)
	if err == nil || !strings.Contains(err.Error(), "no copy") || len(rep.Restored) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, c := range l.Copies {
		if _, err := os.Stat(l.p(c)); err != nil {
			t.Fatalf("a copy was deleted: %v", err)
		}
	}
	if _, err := os.Stat(l.p("/etc/systemd/system/xdr-guard-a.service")); err == nil {
		t.Fatal("something was written with no good copy to trust")
	}
}

func TestUninstall_RemovesAllAndClearsImmutable(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	m, _ := ReadManifest(l)
	f := &fake{}
	if err := Uninstall(l, f.run); err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if _, err := os.Lstat(l.p(e.Path)); err == nil {
			t.Errorf("%s is still there", e.Path)
		}
	}
	for _, p := range []string{l.Manifest, l.Pinned} {
		if _, err := os.Lstat(l.p(p)); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	first := -1
	for i, c := range f.cmds {
		if strings.HasPrefix(c, "chattr -i") && first < 0 {
			first = i
		}
	}
	if first < 0 || f.count("systemctl stop xdr-agent.service") != 1 || f.count("nft delete table inet xdr") != 1 {
		t.Fatalf("commands: %v", f.cmds)
	}
	if err := Uninstall(l, f.run); err != nil {
		t.Fatalf("uninstalling twice: %v", err)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// The agent may be the caller: its wants link goes before any unit file is
// removed, and its stop is the last call.
func TestUninstall_AgentStopLast(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	f := &fake{}
	removed := map[string]bool{} // command -> a file was already gone
	run := func(name string, args ...string) ([]byte, error) {
		_, err := os.Lstat(l.p(l.Manifest))
		removed[name+" "+strings.Join(args, " ")] = err != nil
		return f.run(name, args...)
	}
	if err := Uninstall(l, run); err != nil {
		t.Fatal(err)
	}
	guards := "systemctl disable --now xdr-guard-a.service xdr-guard-b.service xdr-ensure.timer"
	if f.cmds[0] != guards || f.cmds[1] != "systemctl disable xdr-agent.service" || removed[guards] || removed[f.cmds[1]] {
		t.Fatalf("guards, then the agent's disable (no --now), before any removal: %v", f.cmds)
	}
	n := len(f.cmds)
	if f.cmds[n-1] != "systemctl stop xdr-agent.service" || f.cmds[n-2] != "systemctl daemon-reload" || f.count("nft delete table inet xdr") != 1 {
		t.Fatalf("stop is not last: %v", f.cmds)
	}
	if f.count("systemctl disable --now xdr-agent") != 0 || f.count("systemctl stop") != 1 {
		t.Fatalf("%v", f.cmds)
	}
	if !removed[f.cmds[n-1]] {
		t.Fatal("files still there at the stop")
	}
}

// A failed step skips nothing but the agent's stop, and is reported.
func TestUninstall_FailureKeepsTheAgentRunning(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	f := &fake{fail: map[string]error{"systemctl disable --now xdr-guard": errors.New("boom")}}
	err := Uninstall(l, f.run)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("the failed step is not reported: %v", err)
	}
	if f.count("systemctl stop") != 0 {
		t.Fatalf("the agent was stopped after a failure: %v", f.cmds)
	}
	if _, serr := os.Lstat(l.p(l.Manifest)); serr == nil {
		t.Fatal("a failed guard stop skipped the file removal")
	}
}

// What ensure had to do is left for the agent, which reports it as a tamper
// incident; a quiet ensure leaves nothing.
func TestEnsure_LeavesANoteOfWhatItDid(t *testing.T) {
	l := testLayout(t)
	if _, err := Install(l, (&fake{}).run, binary(t, "#!/bin/sh\necho agent\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := Ensure(l, (&fake{}).run); err != nil {
		t.Fatal(err)
	}
	if n := TakeNotes(l); len(n) != 0 {
		t.Fatalf("a quiet ensure left %+v", n)
	}
	write(t, l.p(l.Copies[2]), "corrupt", 0o755)
	if _, err := Ensure(l, (&fake{active: map[string]string{"xdr-guard-b.service": "inactive"}}).run); err != nil {
		t.Fatal(err)
	}
	n := TakeNotes(l)
	if len(n) != 1 || !contains(n[0].Restored, l.Copies[2]) || !contains(n[0].Started, "xdr-guard-b.service") || n[0].Time.IsZero() {
		t.Fatalf("notes %+v", n)
	}
	if n := TakeNotes(l); len(n) != 0 {
		t.Fatalf("taken twice: %+v", n)
	}
	// One that could not restore says why.
	for _, c := range l.Copies {
		write(t, l.p(c), "corrupt", 0o755)
	}
	Ensure(l, (&fake{}).run)
	if n := TakeNotes(l); len(n) != 1 || !strings.Contains(n[0].Error, "pinned hash") {
		t.Fatalf("notes %+v", n)
	}
}
