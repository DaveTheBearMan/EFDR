package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/config"
	"xdr/internal/rules"
)

// fleetConfig writes a controller directory, an enrolled host's bundle
// and a fleet agent config naming it; it returns the controller dir and
// the config path.
func fleetConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ctl")
	bundle := filepath.Join(t.TempDir(), "fleet")
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "init", "--dir", dir, "--name", "192.0.2.7"}, &so, &se); code != 0 {
		t.Fatalf("init: %s", se.String())
	}
	if code := Run([]string{"controller", "enroll", "--dir", dir, "--host", "web01", "--out", bundle}, &so, &se); code != 0 {
		t.Fatalf("enroll: %s", se.String())
	}
	p := filepath.Join(t.TempDir(), "agent.json")
	body := `{"host":"web01","jump":["192.0.2.7"],"xdr_ports":[7443,2379],"fleet":{"endpoints":["192.0.2.7:2379"],"dir":"` + bundle + `"}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, p
}

func TestSignConfigCLI(t *testing.T) {
	dir, p := fleetConfig(t)
	var so, se bytes.Buffer
	if code := Run([]string{"controller", "sign-config", "--dir", dir, p}, &so, &se); code != 0 {
		t.Fatalf("sign-config: %d %s", code, se.String())
	}
	pub, err := rules.LoadPublic(filepath.Join(dir, "rules.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadSigned(p, pub); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"host":"web01"}`), 0o600)
	if code := Run([]string{"controller", "sign-config", "--dir", dir, bad}, &so, &se); code == 0 {
		t.Fatal("signed a config that does not validate")
	}
	if _, err := os.Stat(bad + ".sig"); err == nil {
		t.Fatal("wrote a signature for an invalid config")
	}
}

func TestAgentCmd_RefusesUnsignedFleetConfig(t *testing.T) {
	_, p := fleetConfig(t)
	var so, se bytes.Buffer
	if code := Run([]string{"agent", "--config", p, "--sensor", "none"}, &so, &se); code == 0 || !strings.Contains(se.String(), "unsigned or tampered") {
		t.Fatalf("exit %d, err %q", code, se.String())
	}
}
