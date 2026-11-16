package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"xdr/internal/config"
	"xdr/internal/model"
)

const (
	healNft = "# Warning: table inet bad is managed by iptables-nft, do not touch!\ntable inet bad { # handle 3\n\tchain input { # handle 1\n\t\ttype filter hook input priority 0; policy accept;\n" +
		"\t\tip saddr 192.0.2.7 drop # handle 4\n\t\ttcp dport 80 drop # handle 5\n\t}\n}\n"
	healRoutes = "default via 203.0.113.1 dev eth0\nblackhole 192.0.2.7\n"
)

// healRig is a rig whose box is cut off: etcd down, no mesh peers. Commands
// are faked: out answers by the command line, run records them.
type healRig struct {
	*rig
	f    *fakeFleet
	m    *fakeMesh
	ran  []string
	outs map[string]string
	deny string
}

func newHealRig(t *testing.T) *healRig {
	r, f := fleetRig(t)
	m := &fakeMesh{}
	r.a.mesh = m
	r.a.cfg.Fleet = &config.Fleet{Endpoints: []string{"198.51.100.5:2379"}}
	f.down = true
	h := &healRig{rig: r, f: f, m: m, outs: map[string]string{
		"nft -a list ruleset": healNft, "ip route": healRoutes,
		"ip rule": "0:\tfrom all lookup local\n", "ip -6 rule": "0:\tfrom all lookup local\n", "ip -6 route": "",
		"ss -H -ltnp": "LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"apache2\",pid=900,fd=4))\n",
		"systemctl list-unit-files --no-legend ssh.service sshd.service": "ssh.service  enabled enabled\nsshd.service alias   -\n",
		"systemctl show -p ActiveState --value ssh.service":              "failed\n",
		"ip -o link show eth0":        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n",
		"ip -o -4 addr show dev eth0": "2: eth0 inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\n",
		"ip route show default":       "default via 203.0.113.1 dev eth0\n",
	}}
	r.a.out = func(name string, args ...string) ([]byte, error) {
		k := strings.Join(append([]string{name}, args...), " ")
		if s, ok := h.outs[k]; ok {
			return []byte(s), nil
		}
		return nil, fmt.Errorf("no such command %q", k)
	}
	r.a.readFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "hosts.deny") {
			return []byte(h.deny), nil
		}
		return nil, fmt.Errorf("no file %s", p)
	}
	r.a.writeFile = func(p string, b []byte) error { h.deny = string(b); return nil }
	r.a.run = func(name string, args ...string) error {
		h.ran = append(h.ran, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	return h
}

func (h *healRig) step() {
	h.a.ladder(h.a.run)
}

// cutOff makes the box isolated: both signals absent for ten seconds.
func (h *healRig) cutOff() {
	h.a.ladder(h.a.run) // starts the clock; not isolated yet
	h.now = h.now.Add(11 * time.Second)
}

func TestIsolated_NeedsBothAndTenSeconds(t *testing.T) {
	h := newHealRig(t)
	a := h.a
	if a.isolated() {
		t.Fatal("isolated at once")
	}
	h.now = h.now.Add(9 * time.Second)
	if a.isolated() {
		t.Fatal("isolated after 9 s")
	}
	h.now = h.now.Add(2 * time.Second)
	if !a.isolated() {
		t.Fatal("not isolated after 11 s of no etcd and no peers")
	}
	// A peer comes back: the clock resets.
	h.m.reach = 1
	if a.isolated() {
		t.Fatal("isolated with a peer reachable")
	}
	h.m.reach = 0
	h.now = h.now.Add(9 * time.Second)
	if a.isolated() {
		t.Fatal("the clock did not restart")
	}
	// etcd back alone is enough to end it.
	h.now = h.now.Add(5 * time.Second)
	h.f.down = false
	if a.isolated() {
		t.Fatal("isolated with etcd connected")
	}
	// No mesh at all counts as no peers.
	h.f.down = true
	a.mesh = nil
	a.isolated()
	h.now = h.now.Add(11 * time.Second)
	if !a.isolated() {
		t.Fatal("a box with no mesh is not isolated")
	}
	// A standalone agent has no etcd to lose.
	a.fleet = nil
	if a.isolated() {
		t.Fatal("a standalone agent is isolated")
	}
}

func TestLadder_NothingWhenNotIsolated(t *testing.T) {
	h := newHealRig(t)
	h.f.down = false
	for i := 0; i < 5; i++ {
		h.now = h.now.Add(time.Minute)
		h.step()
	}
	if len(h.ran) != 0 || len(h.fw.applied) != 0 || len(h.got) != 0 {
		t.Fatalf("ran %q applied %d incidents %+v", h.ran, len(h.fw.applied), h.got)
	}
}

func TestLadder_StepsInOrderAndBacksOff(t *testing.T) {
	h := newHealRig(t)
	h.deny = "ALL: 192.0.2.7\nsshd: 203.0.113.5\n"
	h.cutOff()

	// Step 1: the box's own table, and the isolation incident.
	h.step()
	if len(h.fw.applied) != 1 || len(h.ran) != 0 {
		t.Fatalf("step 1: applied %d ran %q", len(h.fw.applied), h.ran)
	}
	if n := h.kind("isolation"); len(n) != 1 {
		t.Fatalf("isolation incidents %+v", h.got)
	}
	// Before the backoff nothing runs.
	h.now = h.now.Add(time.Second)
	h.step()
	if len(h.fw.applied) != 1 || len(h.ran) != 0 || len(h.kind("tamper")) != 0 {
		t.Fatalf("ran inside the backoff: %q", h.ran)
	}
	// Step 2: the removals, exactly what was named.
	h.now = h.now.Add(2 * time.Second)
	h.step()
	want := []string{
		"nft delete rule inet bad input handle 4",
		"ip route del blackhole 192.0.2.7",
	}
	if strings.Join(h.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("removals %q, want %q", h.ran, want)
	}
	if h.deny != "sshd: 203.0.113.5\n" {
		t.Fatalf("hosts.deny %q", h.deny)
	}
	tamp := h.kind("tamper")
	if len(tamp) != 3 {
		t.Fatalf("tamper incidents %+v", tamp)
	}
	for _, in := range tamp {
		if in.Action != "removed" || in.Severity != model.SevCritical {
			t.Fatalf("incident %+v", in)
		}
	}
	// The backoff doubled: 2 s later is too soon, 4 s is not. Step 3 finds
	// the link whole, step 4 finds nothing on port 22 and restarts sshd.
	h.ran = nil
	h.now = h.now.Add(3 * time.Second)
	h.step()
	if len(h.ran) != 0 {
		t.Fatalf("ran inside the doubled backoff: %q", h.ran)
	}
	h.now = h.now.Add(2 * time.Second)
	h.step() // step 3
	if len(h.ran) != 0 {
		t.Fatalf("link was whole: %q", h.ran)
	}
	h.now = h.now.Add(8 * time.Second)
	h.step() // step 4
	if len(h.ran) != 1 || h.ran[0] != "systemctl restart ssh.service" {
		t.Fatalf("step 4: %q", h.ran)
	}
	// Etcd is back: the end is said, listing what was removed.
	h.f.down = false
	h.now = h.now.Add(time.Second)
	h.step()
	over := h.kind("isolation-over")
	if len(over) != 1 {
		t.Fatalf("isolation-over %+v", h.got)
	}
	for _, s := range []string{"nft delete rule inet bad input handle 4", "ip route del blackhole 192.0.2.7", "ALL: 192.0.2.7"} {
		if !strings.Contains(over[0].Detail, s) {
			t.Fatalf("detail %q misses %q", over[0].Detail, s)
		}
	}
	// Nothing more runs.
	n := len(h.ran)
	h.now = h.now.Add(time.Minute)
	h.step()
	if len(h.ran) != n || len(h.kind("isolation-over")) != 1 {
		t.Fatal("ran after the isolation ended")
	}
}

func TestLadder_ScoredPortAndSshdListening(t *testing.T) {
	h := newHealRig(t)
	h.a.cfg.Scored = append(h.a.cfg.Scored, config.Port{Proto: "tcp", Port: 22}, config.Port{Proto: "tcp", Port: 7443})
	h.outs["nft -a list ruleset"] = "table inet only { # handle 3\n\tchain input { # handle 1\n\t\ttype filter hook input priority 0; policy accept;\n" +
		"\t\ttcp dport 80 drop # handle 5\n\t\ttcp dport 22 drop # handle 6\n\t\tip saddr 192.0.2.7 tcp dport 7443 drop # handle 7\n\t}\n}\n"
	h.outs["iptables-legacy-save"] = "*filter\n-A INPUT -p tcp -m tcp --dport 22 -j DROP\nCOMMIT\n"
	h.outs["ip route"] = "default via 203.0.113.1 dev eth0\n"
	h.outs["ss -H -ltnp"] = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=700,fd=3))\n"
	h.cutOff()
	for i := 0; i < 8; i++ {
		h.step()
		h.now = h.now.Add(31 * time.Second)
	}
	if len(h.ran) != 0 {
		t.Fatalf("ran %q: a scored rule was removed, or ssh restarted while it listened", h.ran)
	}
	// Not scored, the same rules are blockers.
	h = newHealRig(t)
	h.outs["nft -a list ruleset"] = "table inet only { # handle 3\n\tchain input { # handle 1\n\t\ttype filter hook input priority 0; policy accept;\n" +
		"\t\ttcp dport 22 drop # handle 6\n\t}\n}\n"
	h.outs["ip route"] = ""
	h.cutOff()
	h.step()
	h.now = h.now.Add(3 * time.Second)
	h.step()
	if strings.Join(h.ran, "|") != "nft delete rule inet only input handle 6" {
		t.Fatalf("ran %q", h.ran)
	}
}

func TestLadder_IptablesAndIPv6(t *testing.T) {
	h := newHealRig(t)
	h.a.cfg.Peers = []config.Net{pfx("2001:db8::/32")}
	h.outs["nft -a list ruleset"] = ""
	h.outs["ip route"] = ""
	h.outs["iptables-legacy-save"] = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -s 192.0.2.7/32 -j DROP\n-A INPUT -s 203.0.113.5/32 -j DROP\nCOMMIT\n"
	h.outs["ip6tables-legacy-save"] = "*filter\n-A INPUT -s 2001:db8::7/128 -j REJECT --reject-with icmp6-port-unreachable\nCOMMIT\n"
	h.outs["ip -6 rule"] = "0:\tfrom all lookup local\n100:\tfrom all to 2001:db8::7 prohibit\n"
	h.outs["ip -6 route"] = "blackhole 2001:db8::9 dev lo metric 1024\n"
	h.cutOff()
	h.step()
	h.now = h.now.Add(3 * time.Second)
	h.step()
	want := []string{
		"iptables-legacy -t filter -D INPUT -s 192.0.2.7/32 -j DROP",
		"ip6tables-legacy -t filter -D INPUT -s 2001:db8::7/128 -j REJECT --reject-with icmp6-port-unreachable",
		"ip -6 rule del pref 100 from all to 2001:db8::7 prohibit",
		"ip -6 route del blackhole 2001:db8::9 dev lo metric 1024",
	}
	if strings.Join(h.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", h.ran, want)
	}
}

func TestLadder_RestoresLinkAndRoute(t *testing.T) {
	h := newHealRig(t)
	h.a.linkSnap = linkSnap{Link: "eth0", Addr: "203.0.113.5/24", Via: "203.0.113.1"}
	h.outs["ip -o link show eth0"] = "2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"
	h.outs["ip -o -4 addr show dev eth0 scope global"] = ""
	h.outs["ip route show default"] = ""
	h.outs["nft -a list ruleset"] = ""
	h.outs["ip route"] = ""
	h.cutOff()
	for i := 0; i < 3; i++ { // table, removals, link
		h.step()
		h.now = h.now.Add(31 * time.Second)
	}
	want := []string{
		"ip link set eth0 up",
		"ip addr add 203.0.113.5/24 dev eth0",
		"ip route add default via 203.0.113.1 dev eth0",
	}
	if strings.Join(h.ran, "|") != strings.Join(want, "|") {
		t.Fatalf("ran %q, want %q", h.ran, want)
	}
}

func TestLadder_LeavesChangedGatewayAndAddress(t *testing.T) {
	for name, set := range map[string]map[string]string{
		"gateway whole-field (203.0.113.10 is not 203.0.113.1)": {"ip route show default": "default via 203.0.113.10 dev eth0\n"},
		"gateway changed":     {"ip route show default": "default via 192.0.2.1 dev eth0\n"},
		"address changed":     {"ip -o -4 addr show dev eth0 scope global": "2: eth0 inet 203.0.113.77/24 scope global eth0\n"},
		"address whole-field": {"ip -o -4 addr show dev eth0 scope global": "2: eth0 inet 203.0.113.55/24 scope global eth0\n"},
	} {
		h := newHealRig(t)
		h.a.linkSnap = linkSnap{Link: "eth0", Addr: "203.0.113.5/24", Via: "203.0.113.1"}
		h.outs["nft -a list ruleset"], h.outs["ip route"] = "", ""
		for k, v := range set {
			h.outs[k] = v
		}
		h.cutOff()
		for i := 0; i < 3; i++ {
			h.step()
			h.now = h.now.Add(31 * time.Second)
		}
		if len(h.ran) != 0 {
			t.Fatalf("%s: ran %q", name, h.ran)
		}
	}
}

func TestLadder_HostsDenyWrittenAtomically(t *testing.T) {
	h := newHealRig(t)
	h.a.readFile, h.a.writeFile = nil, nil
	h.a.root = t.TempDir()
	deny := filepath.Join(h.a.root, "etc/hosts.deny")
	if err := os.MkdirAll(filepath.Dir(deny), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deny, []byte("ALL: 192.0.2.7\nsshd: 203.0.113.5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(deny)
	h.cutOff()
	h.step()
	h.now = h.now.Add(3 * time.Second)
	h.step()
	b, err := os.ReadFile(deny)
	if err != nil || string(b) != "sshd: 203.0.113.5\n" {
		t.Fatalf("hosts.deny %q %v", b, err)
	}
	after, _ := os.Stat(deny)
	if after.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600 kept", after.Mode().Perm())
	}
	if os.SameFile(before, after) {
		t.Fatal("hosts.deny rewritten in place, not through a rename")
	}
	if ents, _ := os.ReadDir(filepath.Dir(deny)); len(ents) != 1 {
		t.Fatalf("temporary files left: %v", ents)
	}
}

// sshRung runs the ladder to its fourth rung (sshd) and returns what ran.
func (h *healRig) sshRung() []string {
	h.outs["nft -a list ruleset"], h.outs["ip route"] = "", ""
	h.cutOff()
	for i := 0; i < 4; i++ {
		h.step()
		h.now = h.now.Add(31 * time.Second)
	}
	return h.ran
}

func TestLadder_SSHRestartUnitAndPort(t *testing.T) {
	for _, c := range []struct {
		name string
		outs map[string]string
		want string // "" : no restart
	}{
		{"ssh.service failed, nothing on 22", nil, "systemctl restart ssh.service"},
		{"only sshd.service", map[string]string{
			"systemctl list-unit-files --no-legend ssh.service sshd.service": "sshd.service enabled disabled\n",
			"systemctl show -p ActiveState --value sshd.service":             "inactive\n",
		}, "systemctl restart sshd.service"},
		{"no sshd unit at all", map[string]string{
			"systemctl list-unit-files --no-legend ssh.service sshd.service": "",
		}, ""},
		{"sshd listens on another port", map[string]string{
			"ss -H -ltnp": "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=700,fd=3))\n",
		}, ""},
		{"active, configured for 2222", map[string]string{
			"systemctl show -p ActiveState --value ssh.service": "active\n",
			"sshd -T": "port 2222\npermitrootlogin prohibit-password\n",
		}, ""},
		{"active, configured for 22, not listening", map[string]string{
			"systemctl show -p ActiveState --value ssh.service": "active\n",
			"sshd -T": "port 22\npermitrootlogin prohibit-password\n",
		}, "systemctl restart ssh.service"},
		{"active, config unreadable", map[string]string{
			"systemctl show -p ActiveState --value ssh.service": "active\n",
		}, ""},
	} {
		h := newHealRig(t)
		for k, v := range c.outs {
			h.outs[k] = v
		}
		got := strings.Join(h.sshRung(), "|")
		if got != c.want {
			t.Errorf("%s: ran %q, want %q", c.name, got, c.want)
		}
	}
}

// The ladder's commands run without the agent's lock: a slow nft must not
// hold up the gate, the DNS stub or the sweep.
func TestLadder_CommandsRunWithoutTheLock(t *testing.T) {
	h := newHealRig(t)
	h.cutOff()
	h.step() // rung 1, the table
	h.now = h.now.Add(3 * time.Second)
	entered, release := make(chan struct{}), make(chan struct{})
	h.a.run = func(name string, args ...string) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}
	done := make(chan struct{})
	go func() { defer close(done); h.step() }() // rung 2: removals
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the removal never ran")
	}
	locked := make(chan struct{})
	go func() { h.a.mu.Lock(); h.a.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("a.mu held while a ladder command ran")
	}
	close(release)
	<-done
	// What the rung did is still recorded once it finishes.
	if n := len(h.kind("tamper")); n != 2 {
		t.Fatalf("tamper incidents after the rung: %d %+v", n, h.got)
	}
}

func TestLinkSnap_SavedWhenConnectedLoadedAtStart(t *testing.T) {
	h := newHealRig(t)
	h.f.down = false
	path := filepath.Join(t.TempDir(), "link.json")
	h.a.linkFile = path
	h.outs["ip -o route show default"] = "default via 203.0.113.1 dev eth0 proto static\n"
	h.step()
	want := linkSnap{Link: "eth0", Addr: "203.0.113.5/24", Via: "203.0.113.1"}
	if h.a.linkSnap != want {
		t.Fatalf("snapshot %+v", h.a.linkSnap)
	}
	b, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(b), "203.0.113.1") {
		t.Fatalf("saved %q %v", b, err)
	}
	// Not refreshed before the slow cadence; refreshed after it.
	h.outs["ip -o route show default"] = "default via 203.0.113.9 dev eth0\n"
	h.now = h.now.Add(time.Minute)
	h.step()
	if h.a.linkSnap.Via != "203.0.113.1" {
		t.Fatalf("refreshed too soon: %+v", h.a.linkSnap)
	}
	h.now = h.now.Add(linkSnapEvery)
	h.step()
	if h.a.linkSnap.Via != "203.0.113.9" {
		t.Fatalf("not refreshed: %+v", h.a.linkSnap)
	}
	// Cut off, nothing is taken or saved: the network may be red team's.
	h.outs["ip -o route show default"] = "default via 192.0.2.99 dev eth1\n"
	h.f.down = true
	saved, _ := os.ReadFile(path)
	for i := 0; i < 6; i++ {
		h.now = h.now.Add(linkSnapEvery)
		h.step()
	}
	if h.a.linkSnap.Via != "203.0.113.9" {
		t.Fatalf("taken while isolated: %+v", h.a.linkSnap)
	}
	if b, _ := os.ReadFile(path); string(b) != string(saved) {
		t.Fatalf("saved while isolated: %s", b)
	}

	// A fresh agent on a box already cut off with the link down: the saved
	// snapshot is what rung 3 restores.
	h2 := newHealRig(t)
	h2.a.linkFile = path
	h2.a.loadLinkSnap()
	if h2.a.linkSnap.Via != "203.0.113.9" || h2.a.linkSnap.Link != "eth0" {
		t.Fatalf("loaded %+v", h2.a.linkSnap)
	}
	h2.outs["ip -o link show eth0"] = "2: eth0: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"
	h2.outs["ip -o -4 addr show dev eth0 scope global"] = ""
	h2.outs["ip route show default"] = ""
	h2.outs["nft -a list ruleset"], h2.outs["ip route"] = "", ""
	h2.cutOff()
	for i := 0; i < 3; i++ {
		h2.step()
		h2.now = h2.now.Add(31 * time.Second)
	}
	if !slices.Contains(h2.ran, "ip route add default via 203.0.113.9 dev eth0") || !slices.Contains(h2.ran, "ip link set eth0 up") {
		t.Fatalf("ran %q", h2.ran)
	}
}
