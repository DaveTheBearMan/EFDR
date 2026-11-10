package collect

import (
	"testing"

	"xdr/internal/testfs"
)

func TestSnapshot_Fixture(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n", 0o644)
	testfs.File(t, root, "etc/shadow", "root:*:1::::::\nbob:$6$y:1::::::\n", 0o640)
	testfs.File(t, root, "etc/group", "root:x:0:\nsudo:x:27:bob\n", 0o644)
	testfs.File(t, root, "etc/hostname", "db01\n", 0o644)
	testfs.File(t, root, "etc/os-release", "NAME=\"Ubuntu\"\nVERSION=\"24.04.3 LTS (Noble Numbat)\"\n", 0o644)
	testfs.File(t, root, "etc/cron.d/job", "* * * * * root true\n", 0o644)
	b, err := Snapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if b.Schema != 1 || b.Host != "db01" || b.OSRelease != "24.04.3 LTS (Noble Numbat)" {
		t.Fatalf("header %+v", b)
	}
	if len(b.Accounts) != 2 || b.Accounts[1].PwState != "set" || len(b.Groups) != 2 {
		t.Fatalf("accounts %+v groups %+v", b.Accounts, b.Groups)
	}
	if _, ok := b.Files["/etc/cron.d/job"]; !ok {
		t.Fatal("cron file missing")
	}
	if b.Modules != nil {
		t.Fatal("no /proc/modules in fixture: Modules should be nil")
	}
}
