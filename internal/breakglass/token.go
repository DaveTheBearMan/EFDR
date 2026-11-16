package breakglass

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"xdr/internal/sign"
)

// Token is one host's permission for one action in one window.
type Token struct {
	V                  int
	ID, Host, Action   string // Action: "approve-session", "pause" or "uninstall"
	NotBefore, Expires time.Time
}

// Skew is the clock difference between the jump box and a box tolerated
// either side of a token's window.
const Skew = 5 * time.Minute

var (
	errMalformed = errors.New("breakglass: malformed token")
	tokenID      = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Mint is t signed with key: base64url(json) "." base64url(signature).
func Mint(t Token, key ed25519.PrivateKey) string {
	b, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sign.Sign("breakglass", b, key))
}

// Parse checks s's signature and form; Valid checks its window and host.
func Parse(s string, pub ed25519.PublicKey) (Token, error) {
	var t Token
	payload, sig, ok := strings.Cut(strings.TrimSpace(s), ".")
	if !ok {
		return t, errMalformed
	}
	b, err1 := base64.RawURLEncoding.DecodeString(payload)
	sg, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil || len(b) > 1024 {
		return t, errMalformed
	}
	if !sign.Verify("breakglass", b, sg, pub) {
		return t, errors.New("breakglass: bad signature")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil || t.V != 1 || !tokenID.MatchString(t.ID) ||
		!Action(t.Action) || !t.Expires.After(t.NotBefore) {
		return Token{}, errMalformed
	}
	return t, nil
}

// Action reports whether a is one of the actions a token can carry.
func Action(a string) bool { return a == "approve-session" || a == "pause" || a == "uninstall" }

// Valid reports why t does not hold for host at now, or nil.
func (t Token) Valid(host string, now time.Time) error {
	switch {
	case t.Host != host:
		return fmt.Errorf("breakglass: token for another host (%s)", t.Host)
	case now.After(t.Expires.Add(Skew)):
		return fmt.Errorf("breakglass: token expired at %s", t.Expires.UTC().Format(time.RFC3339))
	case now.Before(t.NotBefore.Add(-Skew)):
		return fmt.Errorf("breakglass: token not yet valid (from %s)", t.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// Entry is one spool file: a token, and the session it is for.
type Entry struct{ Token, Session string }

// ParseEntry splits a spool file's content.
func ParseEntry(s string) Entry {
	tok, sess, _ := strings.Cut(s, "\n")
	return Entry{Token: strings.TrimSpace(tok), Session: strings.TrimSpace(sess)}
}

// Paused reports whether dir holds a pause token valid for host at now:
// the gate's way in while the agent is down.
func Paused(dir string, pub ed25519.PublicKey, host string, now time.Time) bool {
	for _, s := range ReadSpool(dir) {
		t, err := Parse(ParseEntry(s).Token, pub)
		if err == nil && t.Action == "pause" && t.Valid(host, now) == nil {
			return true
		}
	}
	return false
}
