package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xdr/internal/model"
	"xdr/internal/rules"
)

func remoteRule(addr string, port uint16, proto string) rules.Rule {
	r := rules.Rule{Kind: "remote", Addr: netip.MustParseAddr(addr), Port: port, Proto: proto, From: "db01", Detail: "egress: x"}
	r.SetID()
	return r
}

func (r *rig) lastTable() string {
	if len(r.fw.applied) == 0 {
		return ""
	}
	return r.fw.applied[len(r.fw.applied)-1].String()
}

func TestBlocks_FromSignedRules(t *testing.T) {
	r := newRig(t)
	set := &rules.Set{Version: 1, Rules: []rules.Rule{remoteRule("203.0.113.9", 4444, "tcp")}}
	r.a.setRules(set)
	if !strings.Contains(r.lastTable(), "ip daddr 203.0.113.9 tcp dport 4444 drop") {
		t.Fatalf("the block is not in the table at once (incidents %+v):\n%s", r.got, r.lastTable())
	}
	got := r.kind("fw-block")
	if len(got) != 1 || got[0].Severity != model.SevMedium || !strings.Contains(got[0].Detail, "203.0.113.9:4444/tcp") || !strings.Contains(got[0].Detail, "db01") {
		t.Fatalf("fw-block: %+v", got)
	}
	n := len(r.fw.applied)
	r.a.setRules(&rules.Set{Version: 2, Rules: set.Rules})
	if len(r.kind("fw-block")) != 1 || len(r.fw.applied) != n {
		t.Fatalf("the same blocks again: %d incidents, %d applies (was %d)", len(r.kind("fw-block")), len(r.fw.applied), n)
	}
	r.a.setRules(&rules.Set{Version: 3})
	if got := r.kind("fw-unblock"); len(got) != 1 || !strings.Contains(got[0].Detail, "203.0.113.9:4444/tcp") {
		t.Fatalf("fw-unblock: %+v", got)
	}
	if strings.Contains(r.lastTable(), "dport 4444 drop") {
		t.Fatalf("the block outlived its rule:\n%s", r.lastTable())
	}
}

func TestBlocks_ProtectedRuleRefused(t *testing.T) {
	r := newRig(t)
	r.a.setRules(&rules.Set{Version: 1, Rules: []rules.Rule{remoteRule("192.0.2.7", 443, "tcp")}}) // the jump box
	if len(r.kind("rules-refused")) != 1 || len(r.kind("fw-block")) != 0 || strings.Contains(r.lastTable(), "dport 443 drop") {
		t.Fatalf("a rule naming the jump box: refused %d, blocks %d\n%s", len(r.kind("rules-refused")), len(r.kind("fw-block")), r.lastTable())
	}
}

func TestBlocks_CapAlertOnce(t *testing.T) {
	r := newRig(t)
	var rs []rules.Rule
	for i := 0; i < 600; i++ {
		rs = append(rs, remoteRule(fmt.Sprintf("203.0.%d.%d", i>>8, i&255), 4444, "tcp"))
	}
	r.a.setRules(&rules.Set{Version: 1, Rules: rs})
	if n := strings.Count(r.lastTable(), "dport 4444 drop"); n != 2*512 { // output and forward
		t.Fatalf("%d drops, want %d", n, 2*512)
	}
	if got := r.kind("fw-block-cap"); len(got) != 1 || got[0].Severity != model.SevHigh {
		t.Fatalf("fw-block-cap: %+v", got)
	}
	r.a.setRules(&rules.Set{Version: 2, Rules: rs})
	r.a.guard()
	if len(r.kind("fw-block-cap")) != 1 {
		t.Fatalf("the cap alert repeated: %d", len(r.kind("fw-block-cap")))
	}
}

func dnsFiles(t *testing.T, root string) []string {
	var out []string
	for _, f := range []string{"etc/hosts", "etc/nsswitch.conf", "etc/resolv.conf"} {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func TestDNS_UntouchedWithoutPin(t *testing.T) {
	r := newRig(t)
	r.a.guard()
	if f := dnsFiles(t, r.root); len(f) != 0 || len(r.kind("dns-files")) != 0 {
		t.Fatalf("without dns.pin the agent wrote %v (%d dns-files incidents)", f, len(r.kind("dns-files")))
	}
	if strings.Contains(r.lastTable(), "dport 53") {
		t.Fatalf("without dns.pin the table drops dns:\n%s", r.lastTable())
	}
	r = newRig(t)
	r.a.cfg.DNS.Pin = true
	r.a.guard()
	if f := dnsFiles(t, r.root); len(f) != 3 {
		t.Fatalf("with dns.pin the files written are %v", f)
	}
}

func TestReload_RefusesPinChange(t *testing.T) {
	r := newRig(t)
	next := *r.a.cfg
	next.DNS.Pin = true
	if err := r.a.reload(&next); err == nil || !strings.Contains(err.Error(), "dns.pin") {
		t.Fatalf("err = %v", err)
	}
}
