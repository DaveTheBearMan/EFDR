package model

import (
	"encoding/json"
	"testing"
)

func TestSeverity_JSONRoundTrip(t *testing.T) {
	for s := SevInfo; s <= SevCritical; s++ {
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var got Severity
		if err := json.Unmarshal(b, &got); err != nil || got != s {
			t.Errorf("%s: got %v, %v", b, got, err)
		}
	}
	var s Severity
	for _, bad := range []string{`"loud"`, `7`, `null`, `"unknown"`} {
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}
