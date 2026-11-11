package fw

import (
	"os"
	"runtime"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// inNetns moves the test into a network namespace of its own. The thread
// is never unlocked, so it dies with the test instead of being reused.
func inNetns(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	runtime.LockOSThread()
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Fatal(err)
	}
}

func applied(t *testing.T) (*Firewall, Ruleset) {
	t.Helper()
	inNetns(t)
	f, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	rs := Build(fixture(), now)
	if err := f.Apply(rs); err != nil {
		t.Fatal(err)
	}
	return f, rs
}

func drifted(t *testing.T, f *Firewall) bool {
	t.Helper()
	d, err := f.Drifted()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// kernel returns the xdr table and its chains by name, as the kernel has them.
func kernel(t *testing.T) (*nftables.Conn, *nftables.Table, map[string]*nftables.Chain) {
	t.Helper()
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	chains, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]*nftables.Chain{}
	var table *nftables.Table
	for _, ch := range chains {
		if ch.Table.Name == "xdr" {
			byName[ch.Name], table = ch, ch.Table
		}
	}
	return c, table, byName
}

var acceptAll = []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}

func TestKernel_ApplyIdempotent(t *testing.T) {
	f, rs := applied(t)
	if err := f.Apply(rs); err != nil {
		t.Fatal(err)
	}
	if drifted(t, f) {
		t.Fatal("drift right after Apply")
	}
	_, _, chains := kernel(t)
	if len(chains) != 3 {
		t.Fatalf("chains: %v", chains)
	}
	for name, want := range map[string][]Rule{"input": rs.Input, "output": rs.Output, "forward": rs.Forward} {
		ch := chains[name]
		if ch == nil || ch.Policy == nil || *ch.Policy != nftables.ChainPolicyDrop || ch.Priority == nil || *ch.Priority != -10 {
			t.Fatalf("chain %s: %+v", name, ch)
		}
		if n := len(rulesOf(t, name)); n != len(want) {
			t.Fatalf("chain %s: %d rules, want %d", name, n, len(want))
		}
	}
}

func rulesOf(t *testing.T, chain string) []rawRule {
	t.Helper()
	all, err := dumpRules()
	if err != nil {
		t.Fatal(err)
	}
	var out []rawRule
	for _, r := range all {
		if r.chain == chain {
			out = append(out, r)
		}
	}
	return out
}

func TestKernel_DriftInsertedRule(t *testing.T) {
	f, rs := applied(t)
	c, table, chains := kernel(t)
	c.InsertRule(&nftables.Rule{Table: table, Chain: chains["output"], Exprs: acceptAll})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if !drifted(t, f) {
		t.Fatal("inserted accept rule not noticed")
	}
	if err := f.Apply(rs); err != nil {
		t.Fatal(err)
	}
	if drifted(t, f) {
		t.Fatal("still drifted after Apply")
	}
}

func TestKernel_DriftSameCountDifferentRule(t *testing.T) {
	f, _ := applied(t)
	c, table, chains := kernel(t)
	rules := rulesOf(t, "output")
	c.DelRule(&nftables.Rule{Table: table, Chain: chains["output"], Handle: rules[len(rules)-1].handle})
	c.AddRule(&nftables.Rule{Table: table, Chain: chains["output"], Exprs: acceptAll})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if !drifted(t, f) {
		t.Fatal("swapped rule not noticed")
	}
}

func TestKernel_DriftPolicyAndExtraChain(t *testing.T) {
	f, rs := applied(t)
	c, table, chains := kernel(t)
	accept := nftables.ChainPolicyAccept
	ch := chains["output"]
	ch.Policy = &accept
	c.AddChain(ch)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if !drifted(t, f) {
		t.Fatal("policy accept not noticed")
	}
	if err := f.Apply(rs); err != nil {
		t.Fatal(err)
	}
	c.AddChain(&nftables.Chain{Name: "extra", Table: table})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if !drifted(t, f) {
		t.Fatal("extra chain not noticed")
	}
}

func TestKernel_DriftTableDeleted(t *testing.T) {
	f, rs := applied(t)
	c, table, _ := kernel(t)
	c.DelTable(table)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if !drifted(t, f) {
		t.Fatal("deleted table not noticed")
	}
	if err := f.Apply(rs); err != nil {
		t.Fatal(err)
	}
	if drifted(t, f) {
		t.Fatal("still drifted after Apply")
	}
}

func TestKernel_Remove(t *testing.T) {
	f, _ := applied(t)
	if err := f.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, table, _ := kernel(t); table != nil {
		t.Fatal("table still there")
	}
	if err := f.Remove(); err != nil {
		t.Fatalf("second Remove: %v", err)
	}
}

// Base chains of other tables are listed; a nat chain on output after
// ours could rewrite a destination we already let through, and is Late.
func TestKernel_ForeignBaseChains(t *testing.T) {
	f, _ := applied(t)
	if got, err := f.Foreign(); err != nil || len(got) != 0 {
		t.Fatalf("fresh netns: %v %v", got, err)
	}
	c, err := nftables.New()
	if err != nil {
		t.Fatal(err)
	}
	nat := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "sneaky"})
	early, late := nftables.ChainPriority(-100), nftables.ChainPriority(0)
	c.AddChain(&nftables.Chain{Name: "pre", Table: nat, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: &early})
	c.AddChain(&nftables.Chain{Name: "post", Table: nat, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: &late})
	c.AddChain(&nftables.Chain{Name: "plain", Table: nat}) // not a base chain
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err := f.Foreign()
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	byName := map[string]BaseChain{}
	for _, b := range got {
		byName[b.Name] = b
	}
	if byName["pre"].Late() || !byName["post"].Late() || byName["post"].Table != "sneaky" || byName["post"].Family != "ip" {
		t.Fatalf("%+v", got)
	}
	if s := byName["post"].String(); s != "ip sneaky/post nat output priority 0" {
		t.Fatalf("String() = %q", s)
	}
}
