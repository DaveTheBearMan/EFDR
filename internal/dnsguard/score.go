package dnsguard

import (
	"math"
	"strings"
)

// Score rates how much a queried name looks like data carried in DNS.
// recent is the number of queries the same process made in the last 10 s.
func Score(name string, recent int) (points int, reasons []string) {
	add := func(n int, reason string) {
		points += n
		reasons = append(reasons, reason)
	}
	labels := strings.Split(name, ".")
	longLabel, random := false, false
	for _, l := range labels {
		longLabel = longLabel || len(l) > 40
		random = random || len(l) >= 16 && entropy(l) > 3.8
	}
	if longLabel {
		add(2, "long-label")
	}
	if len(name) > 100 {
		add(2, "long-name")
	}
	if random {
		add(3, "entropy")
	}
	if len(labels) > 5 {
		add(1, "deep")
	}
	if recent > 20 {
		add(3, "burst")
	}
	return points, reasons
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	var count [256]int
	for i := 0; i < len(s); i++ {
		count[s[i]]++
	}
	var e float64
	for _, n := range count {
		if n > 0 {
			p := float64(n) / float64(len(s))
			e -= p * math.Log2(p)
		}
	}
	return e
}
