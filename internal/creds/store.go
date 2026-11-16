package creds

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"crypto/rand"
)

// User is one account's new credentials, as the agent gets them: hashes
// only. NT is set for Samba accounts; Keys, when not nil, is the whole new
// authorized_keys.
type User struct {
	Hash string   `json:"hash"`
	NT   string   `json:"nt,omitempty"`
	Keys []string `json:"keys,omitempty"`
}

// Set is one rotation for one host, the value at To(host)+"creds".
type Set struct {
	ID       string          `json:"id"`
	Users    map[string]User `json:"users"`
	HostKeys bool            `json:"host_keys,omitempty"` // regenerate the SSH host keys
}

// NewSet hashes passwords for a Set; samba names the accounts that also
// get an NT hash.
func NewSet(passwords map[string]string, samba, keys []string, hostKeys bool) Set {
	id := make([]byte, 8)
	rand.Read(id)
	s := Set{ID: hex.EncodeToString(id), Users: map[string]User{}, HostKeys: hostKeys}
	for name, pw := range passwords {
		u := User{Hash: Hash(pw), Keys: keys}
		if slices.Contains(samba, name) {
			u.NT = NTHash(pw)
		}
		s.Users[name] = u
	}
	return s
}

// Entry is one account's cleartext, kept on the jump box only.
type Entry struct {
	Password string    `json:"password"`
	Service  string    `json:"service"`
	Rotated  time.Time `json:"rotated"`
}

// Store is DIR/creds.json: host → account → Entry.
type Store struct {
	path  string
	Hosts map[string]map[string]Entry `json:"hosts"`
}

// Load reads dir's store; a missing one is empty.
func Load(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "creds.json"), Hosts: map[string]map[string]Entry{}}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if s.Hosts == nil {
		s.Hosts = map[string]map[string]Entry{}
	}
	return s, nil
}

// Put sets host's account.
func (s *Store) Put(host, account string, e Entry) {
	if s.Hosts[host] == nil {
		s.Hosts[host] = map[string]Entry{}
	}
	s.Hosts[host][account] = e
}

// Save writes the store, mode 0600, by temp file and rename.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Block is one "host\tservice\taccount\tpassword" line per entry, sorted,
// for host only unless host is "".
func (s *Store) Block(host string) string {
	var lines []string
	for h, accts := range s.Hosts {
		if host != "" && h != host {
			continue
		}
		for a, e := range accts {
			lines = append(lines, strings.Join([]string{h, e.Service, a, e.Password}, "\t"))
		}
	}
	slices.Sort(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
