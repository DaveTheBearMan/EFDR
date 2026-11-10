package cli

import (
	"bytes"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRun_Version(t *testing.T) {
	code, out, _ := run("version")
	if code != 0 || !strings.HasPrefix(out, "xdr ") {
		t.Fatalf("code=%d out=%q", code, out)
	}
}

func TestRun_Unknown(t *testing.T) {
	code, _, errb := run("bogus")
	if code != 2 || !strings.Contains(errb, `unknown command "bogus"`) {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}

func TestRun_NoArgs(t *testing.T) {
	code, _, errb := run()
	if code != 2 || !strings.Contains(errb, "usage:") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
