package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoad_Defaults(t *testing.T) {
	c, err := load(t, `{"host":"web01","jump":["192.0.2.7"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSHPort != 22 || len(c.XDRPorts) != 1 || c.XDRPorts[0] != 7443 || !c.DHCP || !c.Kill || c.DNS.Listen != "127.0.0.1:53" {
		t.Fatalf("defaults wrong: %+v", c)
	}
	c, err = load(t, `{"jump":["192.0.2.7"],"dhcp":false,"kill":false,"xdr_ports":[9000]}`)
	if err != nil || c.DHCP || c.Kill || len(c.XDRPorts) != 1 || c.XDRPorts[0] != 9000 {
		t.Fatalf("explicit values not kept: %+v %v", c, err)
	}
}

func TestLoad_UnknownFieldRefused(t *testing.T) {
	_, err := load(t, `{"jmup":["192.0.2.7"]}`)
	if err == nil || !strings.Contains(err.Error(), "jmup") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidate_RefusesLockout(t *testing.T) {
	for _, body := range []string{`{"host":"web01"}`, `{"host":"web01","jump":[]}`} {
		_, err := load(t, body)
		if err == nil || !strings.Contains(err.Error(), "jump") {
			t.Fatalf("%s: err = %v", body, err)
		}
	}
}

func TestValidate_Table(t *testing.T) {
	bad := map[string]string{
		"proto":        `"scored":[{"proto":"sctp","port":80}]`,
		"port zero":    `"scored":[{"proto":"tcp","port":0}]`,
		"allow_out":    `"allow_out":[{"to":"192.0.2.3","proto":"icmp","port":1}]`,
		"guard rel":    `"guard_exes":["apache2"]`,
		"dns resolver": `"dns":{"enabled":true}`,
		"dns allow":    `"dns":{"allow":["Bad_Name."]}`,
		"dns hosts":    `"dns":{"hosts":{"a b":"192.0.2.9"}}`,
		"dns listen":   `"dns":{"listen":"localhost"}`,
		"listener exe": `"listeners":[{"proto":"udp","port":68,"exe":""}]`,
		"packet port":  `"listeners":[{"proto":"packet","port":68,"exe":"/usr/lib/systemd/systemd-networkd"}]`,
		"packet exe":   `"listeners":[{"proto":"packet","exe":"networkd"}]`,
		"ssh port":     `"ssh_port":0`,
		"xdr port":     `"xdr_ports":[0]`,
		"gray":         `"gray_users":["a:b"]`,
		"host":         `"host":"web 01"`,
	}
	for name, frag := range bad {
		if _, err := load(t, `{"jump":["192.0.2.7"],`+frag+`}`); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := `{"jump":["192.0.2.7"],"scored":[{"proto":"tcp","port":80}],"guard_exes":["/usr/sbin/apache2"],
	 "dns":{"enabled":true,"resolver":"192.0.2.1","allow":["repo.example.com"],"hosts":{"db01":"192.0.2.3"}},
	 "listeners":[{"proto":"udp","port":68,"exe":"/usr/lib/systemd/systemd-networkd"},{"proto":"packet","exe":"/usr/lib/systemd/systemd-networkd"}],"gray_users":["gray1"]}`
	if _, err := load(t, good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
}

func TestNet_AddrOrCIDR(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.7": "192.0.2.7/32", "2001:db8::1": "2001:db8::1/128", "192.0.2.0/24": "192.0.2.0/24"} {
		var n Net
		if err := n.UnmarshalText([]byte(in)); err != nil || n.Prefix != netip.MustParsePrefix(want) {
			t.Errorf("%s → %v, %v", in, n.Prefix, err)
		}
	}
	var n Net
	if err := n.UnmarshalText([]byte("x")); err == nil {
		t.Error("x accepted")
	}
}

func TestDNSOn_Expiry(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	c := &Config{DNS: DNS{Enabled: true}}
	if !c.DNSOn(now) {
		t.Error("zero expiry should be on")
	}
	c.DNS.Expires = now.Add(-time.Minute)
	if c.DNSOn(now) {
		t.Error("expired switch still on")
	}
	c.DNS.Expires = now.Add(time.Minute)
	if !c.DNSOn(now) {
		t.Error("unexpired switch off")
	}
	c.DNS.Enabled = false
	if c.DNSOn(now) {
		t.Error("disabled switch on")
	}
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load("../../deploy/agent.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Jump) == 0 || len(c.Scored) == 0 || len(c.AllowOut) == 0 || len(c.GrayUsers) != 1 || c.GrayUsers[0] != "gray1" {
		t.Fatalf("example is thin: %+v", c)
	}
}

func TestValidate_Fleet(t *testing.T) {
	base := `{"host":"web01","jump":["192.0.2.7"],"xdr_ports":[7443,2379],`
	for frag, want := range map[string]string{
		`"fleet":{"endpoints":["192.0.2.8:2379"]}}`: "fleet.endpoints: 192.0.2.8:2379 is not in jump",
		`"fleet":{"endpoints":["192.0.2.7:2380"]}}`: "fleet.endpoints: port 2380 is not in xdr_ports",
		`"fleet":{"endpoints":[]}}`:                 "fleet.endpoints: empty",
		`"fleet":{"endpoints":["jump:2379"]}}`:      "fleet.endpoints: \"jump:2379\" is not address:port",
	} {
		if _, err := load(t, base+frag); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", frag, err, want)
		}
	}
	if _, err := load(t, `{"jump":["192.0.2.7"],"xdr_ports":[2379],"fleet":{"endpoints":["192.0.2.7:2379"]}}`); err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("fleet without host: %v", err)
	}
	c, err := load(t, base+`"fleet":{"endpoints":["192.0.2.7:2379"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fleet.Dir != "/etc/xdr/fleet" || c.RulesCache != "/var/lib/xdr/rules.json" {
		t.Fatalf("defaults: %+v %q", c.Fleet, c.RulesCache)
	}
	if c, err := load(t, `{"jump":["192.0.2.7"]}`); err != nil || c.Fleet != nil {
		t.Fatalf("standalone: %+v %v", c, err)
	}
}

func TestProtected(t *testing.T) {
	c, err := load(t, `{"jump":["192.0.2.7"],"peers":["192.0.2.4"],"ssh_from":["198.51.100.0/25"],
	 "allow_out":[{"to":"192.0.2.6","proto":"tcp","port":3306}],"dhcp_server":["192.0.2.254"],
	 "dns":{"resolver":"192.0.2.1"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.Protected() {
		got = append(got, p.String())
	}
	want := []string{"192.0.2.7/32", "192.0.2.4/32", "198.51.100.0/25", "192.0.2.6/32", "192.0.2.1/32", "192.0.2.254/32"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("got %v", got)
	}
}

func TestValidate_Mesh(t *testing.T) {
	base := `{"host":"web01","jump":["192.0.2.7"],"xdr_ports":[7443,2379],"fleet":{"endpoints":["192.0.2.7:2379"]},`
	for frag, want := range map[string]string{
		`"peers":["192.0.2.4"],"mesh":{"port":7444}}`:    "mesh.port: 7444 is not in xdr_ports",
		`"peers":["192.0.2.0/24"],"mesh":{"port":7443}}`: "mesh: peers 192.0.2.0/24 is not one address",
	} {
		if _, err := load(t, base+frag); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", frag, err, want)
		}
	}
	if _, err := load(t, `{"host":"web01","jump":["192.0.2.7"],"mesh":{"port":7443}}`); err == nil || !strings.Contains(err.Error(), "mesh: needs fleet") {
		t.Errorf("no fleet: %v", err)
	}
	c, err := load(t, base+`"peers":["192.0.2.4","2001:db8::4"],"mesh":{"port":7443}}`)
	if err != nil || c.Mesh == nil || c.Mesh.Port != 7443 {
		t.Fatalf("%+v %v", c, err)
	}
}
