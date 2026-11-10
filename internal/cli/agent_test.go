package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/testfs"
)

const exampleConfig = "../../deploy/agent.example.json"

func TestFwPrint(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"fw", "print", "--config", exampleConfig}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	found := false
	for _, line := range strings.Split(out.String(), "\n") {
		found = found || strings.Contains(line, "tcp dport 22 accept")
	}
	if !found {
		t.Fatalf("no ssh rule in:\n%s", out.String())
	}
}

func TestFw_BadConfigExits2(t *testing.T) {
	root := testfs.Root(t)
	testfs.File(t, root, "agent.json", `{"host":"web01"}`, 0o600)
	for _, verb := range []string{"print", "apply", "try"} {
		var out, errb bytes.Buffer
		code := Run([]string{"fw", verb, "--config", filepath.Join(root, "agent.json")}, &out, &errb)
		if code != 2 || !strings.Contains(errb.String(), "jump") || out.Len() != 0 {
			t.Fatalf("fw %s: exit %d, stdout %q, stderr %q", verb, code, out.String(), errb.String())
		}
	}
}

func TestFw_UnknownVerb(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Run([]string{"fw", "flush", "--config", exampleConfig}, &out, &errb); code != 2 {
		t.Fatalf("exit %d", code)
	}
}
