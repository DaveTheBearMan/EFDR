package collect

import (
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/testfs"
)

func names(as []baseline.Account) string {
	var n []string
	for _, a := range as {
		n = append(n, a.Name)
	}
	return strings.Join(n, ",")
}

// Every line glibc would hand to login must come out of the parser with
// the uid glibc would give it; anything else is kept as a Bad entry.
func TestParsePasswd_ReadsWhatGlibcReads(t *testing.T) {
	in := "root:x:0:0:root:/root:/bin/bash\n" +
		"short:x:0:0\n" +
		"plus:x:+0:0:::\n" +
		"space:x: 0:0:::\n" +
		" lead:x:0:0::/root:/bin/sh\n" +
		"# comment\n\n" +
		"big:x:0:0:" + strings.Repeat("a", 2<<20) + ":/root:/bin/sh\n" +
		"after:x:0:0::/root:/bin/sh:with:colons\n" +
		"bob:x:1000:1000::/home/bob:/bin/bash\n" +
		"last:x:0:0::/root:/bin/sh"
	got := ParsePasswd(strings.NewReader(in))
	if names(got) != "root,short,plus,space,lead,big,after,bob,last" {
		t.Fatalf("names %s", names(got))
	}
	for _, a := range got {
		if (a.Name == "bob") != (a.UID != 0) || a.Bad {
			t.Errorf("%s: uid %d bad %v", a.Name, a.UID, a.Bad)
		}
	}
	if got[6].Shell != "/bin/sh:with:colons" || got[7].Home != "/home/bob" {
		t.Errorf("fields: %+v %+v", got[6], got[7])
	}
}

func TestParsePasswd_UnreadableLinesAreKeptAsBad(t *testing.T) {
	got := ParsePasswd(strings.NewReader("garbage\nbob:x:abc:1::/h:/bin/sh\n:x:0:0:::\nok:x:5:5:::\n"))
	if len(got) != 4 || !got[0].Bad || got[0].Name != "garbage" || !got[1].Bad || !got[2].Bad || got[3].Bad || got[3].UID != 5 {
		t.Fatalf("got %+v", got)
	}
}

func TestParsePasswd_EmptyIsCapturedEmpty(t *testing.T) {
	if got := ParsePasswd(strings.NewReader("")); got == nil || len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
	if got := ParseGroup(strings.NewReader("")); got == nil || len(got) != 0 {
		t.Fatalf("got %#v", got)
	}
}

// A password in the passwd field is used as is; shadow is consulted only
// for "x".
func TestParsePasswd_PasswordInPasswdField(t *testing.T) {
	got := ParsePasswd(strings.NewReader("open::1000:1000::/h:/bin/sh\nown:$6$abc:0:0::/:/bin/sh\nnorm:x:5:5:::\n"))
	ApplyShadow(got, strings.NewReader("open:!:1::::::\nown:!:1::::::\nnorm:!:1::::::\n"))
	if got[0].PwState != "none" || got[1].PwState != "set" || got[2].PwState != "locked" {
		t.Fatalf("got %+v", got)
	}
}

func TestParsePasswd_OddBytesSurviveJSON(t *testing.T) {
	got := ParsePasswd(strings.NewReader("ev\xffil:x:0:0::/ro\xffot:/bin/\xffsh\n"))
	if len(got) != 1 || !strings.HasPrefix(got[0].Name, "b64:") || !strings.HasPrefix(got[0].Home, "b64:") || !strings.HasPrefix(got[0].Shell, "b64:") {
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
	got := ParseGroup(strings.NewReader("sudo:x:27:alice,bob\nempty:x:5:\nshort:x: +0\nbad\n"))
	if len(got) != 4 || got[0].GID != 27 || len(got[0].Members) != 2 || got[0].Members[1] != "bob" || len(got[1].Members) != 0 {
		t.Fatalf("got %+v", got)
	}
	if got[2].Name != "short" || got[2].GID != 0 || got[2].Bad || !got[3].Bad {
		t.Fatalf("got %+v", got)
	}
}

func TestApplyShadow_ShortLine(t *testing.T) {
	accts := []baseline.Account{{Name: "a"}}
	ApplyShadow(accts, strings.NewReader("a:\n"))
	if accts[0].PwState != "none" {
		t.Fatalf("got %+v", accts)
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
