package agent

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/config"
	"xdr/internal/rules"
)

// An enrolled box's config cannot shed its signature by dropping the fleet
// section: the rule key at the default place still demands one.
func TestLoadConfig_EnrolledBoxNeedsSignature(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	old := defaultFleetPub
	defaultFleetPub = filepath.Join(dir, "rules.pub")
	t.Cleanup(func() { defaultFleetPub = old })
	p := filepath.Join(dir, "agent.json")
	body := []byte(`{"host":"web01","jump":["192.0.2.7"]}`)
	os.WriteFile(p, body, 0o600)
	if _, err := loadConfig(p); err != nil {
		t.Fatalf("not enrolled: %v", err)
	}
	if err := rules.WritePublic(defaultFleetPub, pub); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "unsigned or tampered") {
		t.Fatalf("enrolled, unsigned: %v", err)
	}
	os.WriteFile(p+".sig", config.Signature(body, key), 0o600)
	if _, err := loadConfig(p); err != nil {
		t.Fatalf("enrolled, signed: %v", err)
	}
}
