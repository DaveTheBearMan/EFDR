// Package sign is ed25519 signing scoped by purpose: a signature made for
// one purpose (the agent config, a break-glass token) never verifies as
// another.
package sign

import "crypto/ed25519"

// scoped is the bytes actually signed: "xdr/" + purpose + NUL + msg.
func scoped(purpose string, msg []byte) []byte {
	b := make([]byte, 0, len("xdr/")+len(purpose)+1+len(msg))
	b = append(b, "xdr/"...)
	b = append(b, purpose...)
	b = append(b, 0)
	return append(b, msg...)
}

// Sign signs msg for purpose.
func Sign(purpose string, msg []byte, key ed25519.PrivateKey) []byte {
	return ed25519.Sign(key, scoped(purpose, msg))
}

// Verify reports whether sig is pub's signature of msg for purpose.
func Verify(purpose string, msg, sig []byte, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, scoped(purpose, msg), sig)
}
