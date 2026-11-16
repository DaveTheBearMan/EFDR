package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"xdr/internal/collect"
	"xdr/internal/sign"
)

// DefaultFleetDir is where an agent's fleet bundle lives when its config
// does not say.
const DefaultFleetDir = "/etc/xdr/fleet"

// LoadSigned is Load for a config that must carry the jump box's
// signature: path+".sig" holds the base64 of pub's "config" signature of
// path's bytes. The bytes parsed are the bytes verified.
func LoadSigned(path string, pub ed25519.PublicKey) (*Config, error) {
	data, err := collect.ReadFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("config: unsigned or tampered (%s.sig)", path)
	raw, err := collect.ReadFile(path+".sig", 1<<10)
	if err != nil {
		return nil, bad
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || !sign.Verify("config", data, sig, pub) {
		return nil, bad
	}
	return Parse(data)
}

// Signature is the content of path+".sig" for data.
func Signature(data []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(sign.Sign("config", data, key)) + "\n")
}
