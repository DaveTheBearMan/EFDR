package collect

import (
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func TestParsePasswd_Malformed(t *testing.T) {
	in := "root:x:0:0:root:/root:/bin/bash\ngarbage\nbob:x:abc:1::/h:/bin/sh\ntoor:x:0:0::/root:/bin/bash\n"
	got := ParsePasswd(strings.NewReader(in))
	if len(got) != 2 || got[0].Name != "root" || got[1].Name != "toor" || got[1].UID != 0 || got[1].Shell != "/bin/bash" {
		t.Fatalf("got %+v", got)
	}
}

func TestApplyShadow_States(t *testing.T) {
	accts := []baseline.Account{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	ApplyShadow(accts, strings.NewReader("a:!:1::::::\nb::1::::::\nc:$6$x:1::::::\n"))
	if accts[0].PwState != "locked" || accts[1].PwState != "none" || accts[2].PwState != "set" || len(accts[2].PwDigest) != 64 {
		t.Fatalf("got %+v", accts)
	}
}

func TestParseGroup(t *testing.T) {
	got := ParseGroup(strings.NewReader("sudo:x:27:alice,bob\nempty:x:5:\nbad\n"))
	if len(got) != 2 || got[0].GID != 27 || len(got[0].Members) != 2 || got[0].Members[1] != "bob" || len(got[1].Members) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestModules_AbsentIsNil(t *testing.T) {
	if m := Modules(testfs.Root(t)); m != nil {
		t.Fatalf("want nil, got %v", m)
	}
	root := testfs.Root(t)
	testfs.File(t, root, "proc/modules", "nf_tables 1 0 - Live 0x0\nbpf 2 0 - Live 0x0\n", 0o444)
	m := Modules(root)
	if len(m) != 2 || m[0] != "bpf" || m[1] != "nf_tables" {
		t.Fatalf("got %v", m)
	}
}
