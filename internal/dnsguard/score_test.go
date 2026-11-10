package dnsguard

import (
	"slices"
	"strings"
	"testing"
)

func TestScore(t *testing.T) {
	long := strings.Repeat("a", 45)
	for _, c := range []struct {
		name   string
		recent int
		points int // -1: do not check
		reason string
	}{
		{"www.example.com", 0, 0, ""},
		{"kubernetes-dashboard.example.com", 0, 0, ""},
		{"mfzwizlomnxw2idbonsg633omruw4zy.t.example.com", 0, 3, "entropy"},
		{long + ".example.com", 0, 2, "long-label"},
		{"a.b.c.d.e.example.com", 0, 1, "deep"},
		{"www.example.com", 21, 3, "burst"},
		{"www.example.com", 20, 0, ""},
		{strings.Repeat("abcdefghij.", 10) + "example.com", 0, 3, "long-name"},
		{"", 0, 0, ""},
	} {
		points, reasons := Score(c.name, c.recent)
		if points != c.points || (c.reason == "") != (len(reasons) == 0) || c.reason != "" && !slices.Contains(reasons, c.reason) {
			t.Errorf("Score(%q, %d) = %d %v, want %d %q", c.name, c.recent, points, reasons, c.points, c.reason)
		}
	}
}
