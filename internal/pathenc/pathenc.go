// Package pathenc encodes filesystem paths so they survive JSON round trips.
//
// Linux paths are arbitrary bytes; encoding/json replaces invalid UTF-8 with
// U+FFFD, which would make a hostile filename compare unequal to itself after
// a save/load. Plain paths pass through unchanged; anything else is stored as
// "b64:" + standard base64.
package pathenc

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const prefix = "b64:"

// Encode returns p unchanged when it is valid UTF-8 without newlines and
// without the b64: prefix, and the base64 form otherwise.
func Encode(p string) string {
	if utf8.ValidString(p) && !strings.ContainsRune(p, '\n') && !strings.HasPrefix(p, prefix) {
		return p
	}
	return prefix + base64.StdEncoding.EncodeToString([]byte(p))
}

// Decode reverses Encode.
func Decode(s string) (string, error) {
	if !strings.HasPrefix(s, prefix) {
		return s, nil
	}
	b, err := base64.StdEncoding.DecodeString(s[len(prefix):])
	return string(b), err
}
