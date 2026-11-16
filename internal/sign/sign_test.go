package sign

import (
	"crypto/ed25519"
	"testing"
)

func TestSign_PurposeScoped(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	msg := []byte(`{"host":"web01"}`)
	sig := Sign("config", msg, key)
	if !Verify("config", msg, sig, pub) {
		t.Fatal("own signature refused")
	}
	if Verify("breakglass", msg, sig, pub) {
		t.Error("verified under another purpose")
	}
	flipped := append([]byte(nil), msg...)
	flipped[3] ^= 1
	if Verify("config", flipped, sig, pub) {
		t.Error("verified a changed message")
	}
	if Verify("config", msg, sig, other) {
		t.Error("verified with another key")
	}
	if Verify("config", msg, sig[:10], pub) || Verify("config", msg, sig, pub[:5]) {
		t.Error("short signature or key accepted")
	}
}
