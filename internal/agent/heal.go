package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xdr/internal/heal"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/sshgate"
)

const (
	isolatedAfter = 10 * time.Second
	ladderFirst   = 2 * time.Second
	ladderMax     = 30 * time.Second
	ladderSteps   = 4
)

// linkSnap is the box's network as the agent first found it: the link, its
// address and the default route's gateway. Empty fields are not restored.
type linkSnap struct {
	Link string // eth0
	Addr string // 203.0.113.5/24
	Via  string // 203.0.113.1
}

// ladderState is where the reconnect ladder stands. The agent's lock guards it.
type ladderState struct {
	since   time.Time // the signals went away
	active  bool      // isolation was said and not yet ended
	step    int       // the next rung, 0-based
	next    time.Time // no rung before this
	backoff time.Duration
	removed []string // what was removed this time
}

func (a *agent) output(name string, args ...string) ([]byte, error) {
	if a.out != nil {
		return a.out(name, args...)
	}
	return outputCmd(name, args...)
}

func (a *agent) readF(path string) ([]byte, error) {
	if a.readFile != nil {
		return a.readFile(path)
	}
	return os.ReadFile(path)
}

func (a *agent) writeF(path string, b []byte) error {
	if a.writeFile != nil {
		return a.writeFile(path, b)
	}
	return writeAtomic(path, b, 0o644)
}

// writeAtomic replaces path through a temporary file in its directory and a
// rename, so a reader never sees half a file. An existing file's mode and
// owner are kept; a new one gets mode.
func writeAtomic(path string, b []byte, mode os.FileMode) error {
	uid, gid := -1, -1
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
		if s, ok := st.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(s.Uid), int(s.Gid)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".xdr-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, mode)
	}
	if err == nil && uid >= 0 && (uid != os.Getuid() || gid != os.Getgid()) {
		err = os.Chown(name, uid, gid)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// isolated reports whether the box has lost etcd and every mesh peer for
// isolatedAfter. A standalone agent has no etcd to lose, so is never
// isolated. The caller holds a.mu.
func (a *agent) isolated() bool {
	if a.fleet == nil || a.fleet.Connected() || (a.mesh != nil && a.mesh.Reachable() > 0) {
		a.heal.since = time.Time{}
		return false
	}
	now := a.now()
	if a.heal.since.IsZero() {
		a.heal.since = now
	}
	return now.Sub(a.heal.since) >= isolatedAfter
}

// fleetNets is every address red team gains by cutting off: the jump hosts,
// the peers and the controller's etcd endpoints.
func (a *agent) fleetNets() []netip.Prefix {
	var out []netip.Prefix
	for _, n := range a.cfg.Jump {
		out = append(out, n.Prefix)
	}
	for _, n := range a.cfg.Peers {
		out = append(out, n.Prefix)
	}
	if a.cfg.Fleet != nil {
		for _, e := range a.cfg.Fleet.Endpoints {
			if ap, err := netip.ParseAddrPort(e); err == nil {
				out = append(out, netip.PrefixFrom(ap.Addr().Unmap(), ap.Addr().Unmap().BitLen()))
			}
		}
	}
	return out
}

// agentPorts is every port the agent needs open: ssh, XDR's, the mesh's and
// etcd's.
func (a *agent) agentPorts() []uint16 {
	var out []uint16
	if a.cfg.SSHPort != 0 {
		out = append(out, a.cfg.SSHPort)
	}
	out = append(out, a.cfg.XDRPorts...)
	if a.cfg.Mesh != nil {
		out = append(out, a.cfg.Mesh.Port)
	}
	if a.cfg.Fleet != nil {
		for _, e := range a.cfg.Fleet.Endpoints {
			if ap, err := netip.ParseAddrPort(e); err == nil {
				out = append(out, ap.Port())
			}
		}
	}
	return out
}

// ladder, called every few seconds, does one rung of the reconnect ladder
// when the box is isolated and the backoff has passed: 1 the agent's own
// table, 2 every blocker the finders name, 3 the link, address and route
// of the snapshot, 4 sshd when nothing listens on its port. After the last
// it starts over, as long as the box is isolated. The backoff starts at 2 s
// and doubles to 30 s; it and the rungs reset when the isolation ends.
func (a *agent) ladder(run sshgate.Runner) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.uninstalled {
		return
	}
	h := &a.heal
	if !a.isolated() {
		if h.active {
			detail := "reconnected; nothing had to be removed"
			if len(h.removed) > 0 {
				detail = "reconnected; removed: " + strings.Join(h.removed, "; ")
			}
			a.record(incident.Incident{Kind: "isolation-over", Action: "healed", Severity: model.SevMedium, Detail: detail})
		}
		*h = ladderState{since: h.since}
		return
	}
	now := a.now()
	if !h.active {
		h.active, h.backoff, h.step = true, ladderFirst, 0
		a.record(incident.Incident{Kind: "isolation", Action: "alert", Severity: model.SevHigh,
			Detail: "no etcd and no mesh peer for " + isolatedAfter.String() + ": undoing the isolation"})
	}
	if now.Before(h.next) {
		return
	}
	switch h.step {
	case 0:
		a.syncTable(now)
	case 1:
		a.removeBlockers(run)
	case 2:
		a.restoreLink(run)
	case 3:
		a.restartSSH(run)
	}
	h.step = (h.step + 1) % ladderSteps
	h.next = now.Add(h.backoff)
	h.backoff = min(h.backoff*2, ladderMax)
}

// removed records one thing taken out, or why it was not.
func (a *agent) removed(what string, err error) {
	in := incident.Incident{Kind: "tamper", Action: "removed", Severity: model.SevCritical,
		Detail: "isolating rule removed: " + what}
	if err != nil {
		in.Action, in.Detail = "remove-failed", "isolating rule could not be removed: "+what+": "+err.Error()
	} else {
		a.heal.removed = append(a.heal.removed, what)
	}
	a.record(in)
}

// removeBlockers finds what cuts the box off and removes exactly what the
// parsers name, each as its own argv, never through a shell.
func (a *agent) removeBlockers(run sshgate.Runner) {
	fleet, ports, scored := a.fleetNets(), a.agentPorts(), a.cfg.Scored
	if b, err := a.output("nft", "-a", "list", "ruleset"); err == nil {
		for _, t := range heal.NftBlockers(string(b), fleet, ports, scored) {
			for _, r := range t.Rules {
				args := []string{"delete", "rule", t.Family, t.Name, r.Chain, "handle", strconv.FormatUint(r.Handle, 10)}
				a.removed("nft "+strings.Join(args, " "), run("nft", args...))
			}
		}
	}
	for _, v := range [][2]string{{"iptables-legacy-save", "iptables-legacy"}, {"ip6tables-legacy-save", "ip6tables-legacy"}} {
		if b, err := a.output(v[0]); err == nil {
			for _, args := range heal.IptablesBlockers(string(b), fleet, ports, scored) {
				a.removed(v[1]+" "+strings.Join(args, " "), run(v[1], args...))
			}
		}
	}
	for _, v6 := range []bool{false, true} {
		pre := []string{}
		if v6 {
			pre = []string{"-6"}
		}
		rules, _ := a.output("ip", append(pre, "rule")...)
		routes, _ := a.output("ip", append(pre, "route")...)
		for _, line := range heal.RouteBlockers(string(rules), string(routes), fleet) {
			f := strings.Fields(line)
			if v6 { // "ip rule del ..." becomes "ip -6 rule del ..."
				f = append([]string{f[0], "-6"}, f[1:]...)
			}
			a.removed(strings.Join(f, " "), run(f[0], f[1:]...))
		}
	}
	deny := filepath.Join(a.root, "etc/hosts.deny")
	if b, err := a.readF(deny); err == nil {
		if lines := heal.DenyLines(string(b), fleet); len(lines) > 0 {
			var keep []string
			for _, l := range strings.Split(string(b), "\n") {
				if !slices.Contains(lines, strings.TrimSpace(l)) {
					keep = append(keep, l)
				}
			}
			werr := a.writeF(deny, []byte(strings.Join(keep, "\n")))
			for _, l := range lines {
				a.removed("hosts.deny: "+l, werr)
			}
		}
	}
}

// takeLinkSnap records the link, address and default gateway as they are
// now, for restoreLink. It is best effort: what cannot be read is left out.
func (a *agent) takeLinkSnap() {
	b, err := a.output("ip", "-o", "route", "show", "default")
	if err != nil {
		return
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var s linkSnap
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			s.Via = f[i+1]
		case "dev":
			s.Link = f[i+1]
		}
	}
	if s.Link != "" {
		if b, err := a.output("ip", "-o", "-4", "addr", "show", "dev", s.Link); err == nil {
			g := strings.Fields(string(b))
			for i := 0; i+1 < len(g); i++ {
				if g[i] == "inet" {
					s.Addr = g[i+1]
					break
				}
			}
		}
	}
	a.mu.Lock()
	a.linkSnap = s
	a.mu.Unlock()
}

// restoreLink brings back what the snapshot had and the box lacks.
func (a *agent) restoreLink(run sshgate.Runner) {
	s := a.linkSnap
	if s.Link == "" {
		return
	}
	did := func(what string, err error) {
		in := incident.Incident{Kind: "isolation", Action: "repaired", Severity: model.SevHigh, Detail: what}
		if err != nil {
			in.Action, in.Detail = "alert", what+" failed: "+err.Error()
		} else {
			a.heal.removed = append(a.heal.removed, what)
		}
		a.record(in)
	}
	if b, err := a.output("ip", "-o", "link", "show", s.Link); err == nil && !strings.Contains(string(b), "state UP") && !strings.Contains(string(b), ",UP") && !strings.Contains(string(b), "<UP") {
		did("link "+s.Link+" brought up", run("ip", "link", "set", s.Link, "up"))
	}
	// An address or gateway that is there but different is DHCP's or the
	// admin's doing: only a box with none at all gets the old one back.
	if s.Addr != "" {
		if b, err := a.output("ip", "-o", "-4", "addr", "show", "dev", s.Link, "scope", "global"); err == nil && len(strings.Fields(string(b))) == 0 {
			did("address "+s.Addr+" restored on "+s.Link, run("ip", "addr", "add", s.Addr, "dev", s.Link))
		}
	}
	if s.Via != "" {
		if b, err := a.output("ip", "route", "show", "default"); err == nil && len(strings.Fields(string(b))) == 0 {
			did("default route via "+s.Via+" restored", run("ip", "route", "add", "default", "via", s.Via, "dev", s.Link))
		}
	}
}

// restartSSH restarts sshd when nothing listens on its port: the only case
// where doing so cannot take a service down.
func (a *agent) restartSSH(run sshgate.Runner) {
	port := a.cfg.SSHPort
	if port == 0 {
		return
	}
	b, err := a.output("ss", "-H", "-ltn")
	if err != nil {
		return // cannot tell: leave it
	}
	suffix := ":" + strconv.Itoa(int(port))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 {
			if strings.HasSuffix(f[3], suffix) {
				return
			}
		}
	}
	err = run("systemctl", "restart", "ssh.service")
	in := incident.Incident{Kind: "isolation", Action: "repaired", Severity: model.SevHigh, Detail: fmt.Sprintf("sshd restarted: nothing listened on port %d", port)}
	if err != nil {
		in.Action, in.Detail = "alert", "sshd restart failed: "+err.Error()
	} else {
		a.heal.removed = append(a.heal.removed, "sshd restarted")
	}
	a.record(in)
}
