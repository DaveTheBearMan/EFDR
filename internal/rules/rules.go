// Package rules is the fleet's rule set: narrow kill rules written from
// incidents, checked and signed on the jump box, verified on every agent.
package rules

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"
)

// Rule is one thing every agent kills on sight.
type Rule struct {
	ID     string     `json:"id"`
	Kind   string     `json:"kind"` // hash | remote
	SHA256 string     `json:"sha256,omitempty"`
	Exe    string     `json:"exe,omitempty"` // where it was seen; not matched on
	Addr   netip.Addr `json:"addr,omitzero"`
	Port   uint16     `json:"port,omitempty"`
	Proto  string     `json:"proto,omitempty"`
	From   string     `json:"from"` // the host that proposed it
	Seen   time.Time  `json:"seen"` // when the incident happened
	Detail string     `json:"detail,omitempty"`
}

// Key is what makes two rules the same rule.
func (r *Rule) Key() string {
	if r.Kind == "hash" {
		return "hash:" + r.SHA256
	}
	return "remote:" + netip.AddrPortFrom(r.Addr.Unmap(), r.Port).String() + "/" + r.Proto
}

func (r *Rule) id() string {
	sum := sha256.Sum256([]byte(r.Key()))
	return hex.EncodeToString(sum[:8])
}

// SetID unmaps the address and sets ID from Key.
func (r *Rule) SetID() {
	r.Addr = r.Addr.Unmap()
	r.ID = r.id()
}

// Set is the whole rule set at one version.
type Set struct {
	Version uint64    `json:"version"`
	Issued  time.Time `json:"issued"`
	Rules   []Rule    `json:"rules"`
}

// RemoteKey is the endpoint a remote rule names.
type RemoteKey struct {
	Addr  netip.Addr
	Port  uint16
	Proto string
}

// Index is a set arranged for matching.
type Index struct {
	Hash   map[string]*Rule
	Remote map[RemoteKey]*Rule
}

// Lookup indexes s.
func (s *Set) Lookup() Index {
	ix := Index{Hash: map[string]*Rule{}, Remote: map[RemoteKey]*Rule{}}
	for i := range s.Rules {
		r := &s.Rules[i]
		switch r.Kind {
		case "hash":
			ix.Hash[r.SHA256] = r
		case "remote":
			ix.Remote[RemoteKey{r.Addr.Unmap(), r.Port, r.Proto}] = r
		}
	}
	return ix
}

// Envelope is a signed set as it is stored and sent.
type Envelope struct {
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

// ErrBadSignature means the envelope was not signed by the key given.
var ErrBadSignature = errors.New("rule set: bad signature")

// Sign signs s with key.
func Sign(s *Set, key ed25519.PrivateKey) (Envelope, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Payload: b, Sig: ed25519.Sign(key, b)}, nil
}

// Open verifies e against pub and decodes the set in it.
func Open(e Envelope, pub ed25519.PublicKey) (*Set, error) {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, e.Payload, e.Sig) {
		return nil, ErrBadSignature
	}
	var s Set
	if err := json.Unmarshal(e.Payload, &s); err != nil {
		return nil, fmt.Errorf("rule set: %w", err)
	}
	for _, r := range s.Rules {
		if r.ID != r.id() {
			return nil, fmt.Errorf("rule set: rule id %q does not match its content", r.ID)
		}
	}
	return &s, nil
}

// Marshal encodes e for storage.
func Marshal(e Envelope) ([]byte, error) { return json.Marshal(e) }

// Unmarshal decodes a stored envelope.
func Unmarshal(b []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return Envelope{}, fmt.Errorf("rule set: %w", err)
	}
	return e, nil
}

const (
	pemPublic  = "XDR RULES PUBLIC KEY"
	pemPrivate = "XDR RULES PRIVATE KEY"
)

func writePEM(path, typ string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: typ, Bytes: b}); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readPEM(path, typ string, size int) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != typ || len(blk.Bytes) != size {
		return nil, fmt.Errorf("%s: not a %s", path, typ)
	}
	return blk.Bytes, nil
}

// WritePublic writes pub to a new file.
func WritePublic(path string, pub ed25519.PublicKey) error {
	return writePEM(path, pemPublic, pub, 0o644)
}

// WritePrivate writes key to a new file only its owner can read.
func WritePrivate(path string, key ed25519.PrivateKey) error {
	return writePEM(path, pemPrivate, key.Seed(), 0o600)
}

// LoadPublic reads a key written by WritePublic.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	b, err := readPEM(path, pemPublic, ed25519.PublicKeySize)
	return ed25519.PublicKey(b), err
}

// LoadPrivate reads a key written by WritePrivate, refusing one others
// can read.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if m := st.Mode().Perm(); m&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %s, want 600", path, strconv.FormatUint(uint64(m), 8))
	}
	b, err := readPEM(path, pemPrivate, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(b), nil
}
