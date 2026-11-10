package pathenc

import (
	"strings"
	"testing"
)

func TestEncode_Plain(t *testing.T) {
	if got := Encode("/etc/crontab"); got != "/etc/crontab" {
		t.Fatalf("got %q", got)
	}
}

func TestEncode_Odd(t *testing.T) {
	for _, p := range []string{"/tmp/a\nb", "/tmp/\xff", "b64:x"} {
		e := Encode(p)
		if !strings.HasPrefix(e, "b64:") {
			t.Errorf("Encode(%q)=%q, want b64: prefix", p, e)
		}
		d, err := Decode(e)
		if err != nil || d != p {
			t.Errorf("Decode(Encode(%q))=%q,%v", p, d, err)
		}
	}
}
