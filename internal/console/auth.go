package console

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xdr/internal/creds"
)

const (
	hashRounds  = 100000
	minPassword = 12
	saltChars   = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// SetPassword stores the operator's password hashed (sha512-crypt, 100000
// rounds) in dir/console.json, mode 0600.
func SetPassword(dir, password string) error {
	if len(password) < minPassword {
		return fmt.Errorf("the password must be at least %d characters", minPassword)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = saltChars[int(raw[i])%len(saltChars)]
	}
	b, err := json.Marshal(map[string]string{"hash": creds.SHA512Crypt(password, string(salt), hashRounds)})
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "console.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "console.json"))
}

// CheckPassword reports whether password is the stored one. It reads the
// file on each call, so a new password takes effect at once; a missing or
// damaged file accepts nothing.
func CheckPassword(dir, password string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "console.json"))
	if err != nil {
		return false
	}
	var f struct {
		Hash string `json:"hash"`
	}
	if json.Unmarshal(b, &f) != nil {
		return false
	}
	parts := strings.Split(f.Hash, "$") // "", "6", "rounds=N", salt, sum
	if len(parts) != 5 || parts[1] != "6" || !strings.HasPrefix(parts[2], "rounds=") {
		return false
	}
	rounds, err := strconv.Atoi(strings.TrimPrefix(parts[2], "rounds="))
	if err != nil || rounds < 1000 {
		return false
	}
	got := creds.SHA512Crypt(password, parts[3], rounds)
	return subtle.ConstantTimeCompare([]byte(got), []byte(f.Hash)) == 1
}
