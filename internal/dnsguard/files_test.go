package dnsguard

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"xdr/internal/config"
	"xdr/internal/testfs"
)

var now = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func cfg() *config.Config {
	return &config.Config{
		Host: "web01",
		DNS: config.DNS{
			Listen: "127.0.0.1:53",
			Hosts: map[string]netip.Addr{
				"web01": netip.MustParseAddr("192.0.2.5"),
				"db01":  netip.MustParseAddr("192.0.2.3"),
			},
		},
	}
}

const wantHosts = "127.0.0.1 localhost\n127.0.1.1 web01\n::1 localhost ip6-localhost ip6-loopback\n192.0.2.3 db01\n192.0.2.5 web01\n"

const nsswitchFile = "# /etc/nsswitch.conf\npasswd:         files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\nnetworks:       files\n"

func etc(t *testing.T) string {
	t.Helper()
	root := testfs.Root(t)
	testfs.File(t, root, "/etc/hosts", "127.0.0.1 localhost\n", 0o644)
	testfs.File(t, root, "/etc/nsswitch.conf", nsswitchFile, 0o644)
	testfs.File(t, root, "/run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n", 0o644)
	testfs.Symlink(t, root, "/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
	return root
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assert(t *testing.T, root string, c *config.Config) []string {
	t.Helper()
	changed, err := Assert(root, c, now)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestAssert_HostsExact(t *testing.T) {
	root := etc(t)
	assert(t, root, cfg())
	if got := read(t, root, "/etc/hosts"); got != wantHosts {
		t.Fatalf("hosts:\n%s", got)
	}
	if st, _ := os.Stat(filepath.Join(root, "/etc/hosts")); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestAssert_NsswitchOffThenOn(t *testing.T) {
	root := etc(t)
	c := cfg()
	assert(t, root, c)
	off := strings.Replace(nsswitchFile, "files mdns4_minimal [NOTFOUND=return] dns", "files", 1)
	if got := read(t, root, "/etc/nsswitch.conf"); got != off {
		t.Fatalf("off:\n%s", got)
	}
	c.DNS.Enabled, c.DNS.Resolver = true, netip.MustParseAddr("192.0.2.1")
	if changed := assert(t, root, c); !reflect.DeepEqual(changed, []string{"/etc/nsswitch.conf"}) {
		t.Fatalf("changed %v", changed)
	}
	if got := read(t, root, "/etc/nsswitch.conf"); got != strings.Replace(off, "files\nnetworks", "files dns\nnetworks", 1) {
		t.Fatalf("on:\n%s", got)
	}
	// The switch runs out: back to files only.
	c.DNS.Expires = now.Add(-time.Minute)
	assert(t, root, c)
	if got := read(t, root, "/etc/nsswitch.conf"); got != off {
		t.Fatalf("expired:\n%s", got)
	}
}

func TestAssert_NsswitchHostsLineAppended(t *testing.T) {
	root := etc(t)
	testfs.File(t, root, "/etc/nsswitch.conf", "passwd: files", 0o644)
	assert(t, root, cfg())
	if got := read(t, root, "/etc/nsswitch.conf"); got != "passwd: files\nhosts:          files\n" {
		t.Fatalf("%q", got)
	}
}

func TestAssert_ResolvConfSymlinkReplaced(t *testing.T) {
	root := etc(t)
	assert(t, root, cfg())
	st, err := os.Lstat(filepath.Join(root, "/etc/resolv.conf"))
	if err != nil || !st.Mode().IsRegular() {
		t.Fatalf("resolv.conf: %v %v", st, err)
	}
	if got := read(t, root, "/etc/resolv.conf"); got != "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n" {
		t.Fatalf("%q", got)
	}
	if got := read(t, root, "/run/systemd/resolve/stub-resolv.conf"); got != "nameserver 127.0.0.53\n" {
		t.Fatalf("link target rewritten: %q", got)
	}
}

func TestAssert_SecondRunChangesNothing(t *testing.T) {
	root := etc(t)
	first := assert(t, root, cfg())
	if !reflect.DeepEqual(first, []string{"/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf"}) {
		t.Fatalf("first run changed %v", first)
	}
	mtimes := func() (out []time.Time) {
		for _, f := range first {
			st, err := os.Lstat(filepath.Join(root, f))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, st.ModTime())
		}
		return out
	}
	before := mtimes()
	time.Sleep(20 * time.Millisecond)
	if changed := assert(t, root, cfg()); len(changed) != 0 {
		t.Fatalf("second run changed %v", changed)
	}
	if !reflect.DeepEqual(before, mtimes()) {
		t.Fatal("a file was rewritten")
	}
}

func TestAssert_DriftRepaired(t *testing.T) {
	root := etc(t)
	assert(t, root, cfg())
	f, err := os.OpenFile(filepath.Join(root, "/etc/hosts"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("203.0.113.9 scoring\n")
	f.Close()
	if changed := assert(t, root, cfg()); !reflect.DeepEqual(changed, []string{"/etc/hosts"}) {
		t.Fatalf("changed %v", changed)
	}
	if got := read(t, root, "/etc/hosts"); got != wantHosts {
		t.Fatalf("hosts:\n%s", got)
	}
}

func TestAssert_WrongModeRepaired(t *testing.T) {
	root := etc(t)
	assert(t, root, cfg())
	if err := os.Chmod(filepath.Join(root, "/etc/hosts"), 0o666); err != nil {
		t.Fatal(err)
	}
	if changed := assert(t, root, cfg()); !reflect.DeepEqual(changed, []string{"/etc/hosts"}) {
		t.Fatalf("changed %v", changed)
	}
	if st, _ := os.Stat(filepath.Join(root, "/etc/hosts")); st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestAssert_FifoInPlace(t *testing.T) {
	root := etc(t)
	testfs.Remove(t, root, "/etc/hosts")
	testfs.Fifo(t, root, "/etc/hosts")
	done := make(chan []string, 1)
	go func() { done <- assert(t, root, cfg()) }()
	select {
	case changed := <-done:
		if len(changed) != 3 || changed[0] != "/etc/hosts" {
			t.Fatalf("changed %v", changed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on the fifo")
	}
	if got := read(t, root, "/etc/hosts"); got != wantHosts {
		t.Fatalf("hosts:\n%s", got)
	}
}

func TestAssert_MissingFilesCreated(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "/etc/passwd", "", 0o644)
	if changed := assert(t, root, cfg()); len(changed) != 3 {
		t.Fatalf("changed %v", changed)
	}
}

// With no host name in the config there is no 127.0.1.1 line, rather
// than one that names nothing.
func TestAssert_HostsWithoutHostName(t *testing.T) {
	root := etc(t)
	c := cfg()
	c.Host = ""
	assert(t, root, c)
	got := read(t, root, "/etc/hosts")
	if strings.Contains(got, "127.0.1.1") || !strings.Contains(got, "127.0.0.1 localhost\n") {
		t.Fatalf("hosts:\n%s", got)
	}
}

func TestSaveRestore_PutsTheBoxBack(t *testing.T) {
	root := etc(t)
	backup := filepath.Join(t.TempDir(), "dns-orig")
	hosts0, ns0 := read(t, root, "/etc/hosts"), read(t, root, "/etc/nsswitch.conf")
	if err := Save(root, backup); err != nil {
		t.Fatal(err)
	}
	assert(t, root, cfg())
	if !LooksPinned(root) {
		t.Fatal("not pinned after Assert")
	}
	// Saving again, with the box pinned, must not keep the pinned files as the originals.
	if err := Save(root, backup); err != nil {
		t.Fatal(err)
	}
	changed, err := Restore(root, backup)
	if err != nil || len(changed) != 3 {
		t.Fatalf("changed %v, err %v", changed, err)
	}
	if got := read(t, root, "/etc/hosts"); got != hosts0 {
		t.Errorf("hosts:\n%s", got)
	}
	if got := read(t, root, "/etc/nsswitch.conf"); got != ns0 {
		t.Errorf("nsswitch:\n%s", got)
	}
	target, err := os.Readlink(filepath.Join(root, "/etc/resolv.conf"))
	if err != nil || target != "../run/systemd/resolve/stub-resolv.conf" {
		t.Errorf("resolv.conf: %q %v", target, err)
	}
	if LooksPinned(root) {
		t.Error("still pinned")
	}
	if _, err := os.Stat(backup); err == nil {
		t.Error("backup left behind")
	}
	if changed, err := Restore(root, backup); err != nil || changed != nil {
		t.Errorf("restore with no backup: %v %v", changed, err)
	}
}

func TestSave_PinnedBoxHasNoBackup(t *testing.T) {
	root := etc(t)
	assert(t, root, cfg()) // an earlier agent pinned it, saving nothing
	backup := filepath.Join(t.TempDir(), "dns-orig")
	if err := Save(root, backup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); err == nil {
		t.Fatal("pinned files were saved as the originals")
	}
}
