package diff

import (
	"strings"
	"testing"

	"xdr/internal/baseline"
	"xdr/internal/model"
)

func withAccts(a []baseline.Account, g []baseline.Group, m []string) *baseline.Baseline {
	return &baseline.Baseline{Schema: 1, Files: map[string]baseline.FileEntry{}, Accounts: a, Groups: g, Modules: m}
}

var rootAcct = baseline.Account{Name: "root", Shell: "/bin/bash", Home: "/root", PwState: "locked", PwDigest: "d0"}

func TestDiffAccounts_SecondUID0(t *testing.T) {
	toor := baseline.Account{Name: "toor", UID: 0, Shell: "/bin/bash", Home: "/root"}
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct}, nil, nil), withAccts([]baseline.Account{rootAcct, toor}, nil, nil)))
	if f.Kind != model.KindAdded || f.Category != "account" || f.Severity != model.SevCritical || f.Subject != "toor" || !strings.Contains(f.Detail, "uid 0") {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_NewUser(t *testing.T) {
	bob := baseline.Account{Name: "bob", UID: 1003, GID: 1003, Shell: "/bin/bash"}
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct}, nil, nil), withAccts([]baseline.Account{rootAcct, bob}, nil, nil)))
	if f.Severity != model.SevHigh || f.Category != "account" {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_UIDBecomesZero(t *testing.T) {
	a := baseline.Account{Name: "svc", UID: 999, Shell: "/usr/sbin/nologin"}
	b := a
	b.UID = 0
	f := one(t, Diff(withAccts([]baseline.Account{a}, nil, nil), withAccts([]baseline.Account{b}, nil, nil)))
	if f.Kind != model.KindAltered || f.Severity != model.SevCritical {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_NologinToBash(t *testing.T) {
	a := baseline.Account{Name: "www-data", UID: 33, Shell: "/usr/sbin/nologin"}
	b := a
	b.Shell = "/bin/bash"
	f := one(t, Diff(withAccts([]baseline.Account{a}, nil, nil), withAccts([]baseline.Account{b}, nil, nil)))
	if f.Severity != model.SevHigh || f.Before != "/usr/sbin/nologin" || f.After != "/bin/bash" {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_PasswordChanged(t *testing.T) {
	b := rootAcct
	b.PwState, b.PwDigest = "set", "d1"
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct}, nil, nil), withAccts([]baseline.Account{b}, nil, nil)))
	if f.Severity != model.SevHigh || !strings.Contains(f.Detail, "password changed") || f.Before != "" || f.After != "" {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_Removed(t *testing.T) {
	bob := baseline.Account{Name: "bob", UID: 1000}
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct, bob}, nil, nil), withAccts([]baseline.Account{rootAcct}, nil, nil)))
	if f.Kind != model.KindRemoved || f.Severity != model.SevMedium {
		t.Fatalf("%+v", f)
	}
}

func TestDiffGroups_SudoMember(t *testing.T) {
	f := one(t, Diff(withAccts(nil, []baseline.Group{{Name: "sudo", GID: 27}}, nil),
		withAccts(nil, []baseline.Group{{Name: "sudo", GID: 27, Members: []string{"mallory"}}}, nil)))
	if f.Category != "group" || f.Severity != model.SevCritical || !strings.Contains(f.Detail, "mallory") {
		t.Fatalf("%+v", f)
	}
}

func TestDiffGroups_OtherMemberAndNewGroup(t *testing.T) {
	fs := Diff(withAccts(nil, []baseline.Group{{Name: "users", GID: 100}}, nil),
		withAccts(nil, []baseline.Group{{Name: "users", GID: 100, Members: []string{"x"}}, {Name: "evil", GID: 5000}}, nil))
	if len(fs) != 2 || fs[0].Severity != model.SevMedium || fs[0].Subject != "evil" || fs[1].Severity != model.SevLow {
		t.Fatalf("%+v", fs)
	}
}

func TestDiffModules_NilSkips(t *testing.T) {
	if fs := Diff(withAccts(nil, nil, nil), withAccts(nil, nil, []string{"diamorphine"})); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	f := one(t, Diff(withAccts(nil, nil, []string{"bpf"}), withAccts(nil, nil, []string{"bpf", "diamorphine"})))
	if f.Category != "module" || f.Severity != model.SevCritical || f.Subject != "diamorphine" {
		t.Fatalf("%+v", f)
	}
}

// An account database present in the baseline but not captured live means
// the comparison did not happen; that must be said, not skipped.
func TestDiff_DatabaseNotCapturedLive(t *testing.T) {
	base := withAccts([]baseline.Account{rootAcct}, []baseline.Group{{Name: "root"}}, []string{"bpf"})
	fs := Diff(base, withAccts(nil, nil, nil))
	if len(fs) != 3 {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if f.Kind != model.KindError || f.Severity != model.SevHigh {
			t.Fatalf("%+v", f)
		}
	}
	// Captured but empty is a real comparison: everything was removed.
	if fs := Diff(base, withAccts([]baseline.Account{}, []baseline.Group{}, []string{})); len(fs) != 3 || fs[0].Kind != model.KindRemoved {
		t.Fatalf("%+v", fs)
	}
}

func TestDiffAccounts_BadLine(t *testing.T) {
	bad := baseline.Account{Name: "toor:x:zero:0", Bad: true}
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct}, nil, nil), withAccts([]baseline.Account{rootAcct, bad}, nil, nil)))
	if f.Kind != model.KindAdded || f.Category != "account" || f.Severity != model.SevHigh || !strings.Contains(f.Detail, "malformed") {
		t.Fatalf("%+v", f)
	}
	if fs := Diff(withAccts([]baseline.Account{rootAcct, bad}, nil, nil), withAccts([]baseline.Account{rootAcct, bad}, nil, nil)); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	g := baseline.Group{Name: "junk", Bad: true}
	f = one(t, Diff(withAccts(nil, []baseline.Group{}, nil), withAccts(nil, []baseline.Group{g}, nil)))
	if f.Category != "group" || f.Severity != model.SevHigh || !strings.Contains(f.Detail, "malformed") {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_DuplicateNameWithUID0(t *testing.T) {
	www := baseline.Account{Name: "www-data", UID: 33, Shell: "/usr/sbin/nologin"}
	dup := www
	dup.UID = 0
	fs := Diff(withAccts([]baseline.Account{www}, nil, nil), withAccts([]baseline.Account{dup, www}, nil, nil))
	if len(fs) == 0 || fs[0].Severity != model.SevCritical || !strings.Contains(fs[0].Detail, "uid 33→0") {
		t.Fatalf("%+v", fs)
	}
}

func TestDiffAccounts_PasswordEmptiedIsCritical(t *testing.T) {
	open := rootAcct
	open.PwState, open.PwDigest = "none", "d1"
	f := one(t, Diff(withAccts([]baseline.Account{rootAcct}, nil, nil), withAccts([]baseline.Account{open}, nil, nil)))
	if f.Severity != model.SevCritical || !strings.Contains(f.Detail, "locked→none") {
		t.Fatalf("%+v", f)
	}
}

func TestDiffAccounts_PrimaryGIDIntoPrivilegedGroup(t *testing.T) {
	bob := baseline.Account{Name: "bob", UID: 1000, GID: 1000}
	groups := []baseline.Group{{Name: "sudo", GID: 27}, {Name: "bob", GID: 1000}, {Name: "users", GID: 100}}
	moved := bob
	moved.GID = 27
	f := one(t, Diff(withAccts([]baseline.Account{bob}, groups, nil), withAccts([]baseline.Account{moved}, groups, nil)))
	if f.Severity != model.SevCritical || !strings.Contains(f.Detail, "gid 1000→27") || !strings.Contains(f.Detail, "sudo") {
		t.Fatalf("%+v", f)
	}
	moved.GID = 0
	if f := one(t, Diff(withAccts([]baseline.Account{bob}, groups, nil), withAccts([]baseline.Account{moved}, groups, nil))); f.Severity != model.SevCritical {
		t.Fatalf("%+v", f)
	}
	moved.GID = 100
	if f := one(t, Diff(withAccts([]baseline.Account{bob}, groups, nil), withAccts([]baseline.Account{moved}, groups, nil))); f.Severity != model.SevMedium {
		t.Fatalf("%+v", f)
	}
}

func TestDiffGroups_GIDChanged(t *testing.T) {
	base := []baseline.Group{{Name: "sudo", GID: 27}, {Name: "games", GID: 60}, {Name: "users", GID: 100}}
	live := []baseline.Group{{Name: "sudo", GID: 100}, {Name: "games", GID: 61}, {Name: "users", GID: 100}}
	fs := Diff(withAccts(nil, base, nil), withAccts(nil, live, nil))
	if len(fs) != 2 || fs[0].Subject != "sudo" || fs[0].Severity != model.SevCritical || !strings.Contains(fs[0].Detail, "gid 27→100") ||
		fs[1].Subject != "games" || fs[1].Severity != model.SevHigh {
		t.Fatalf("%+v", fs)
	}
	zero := []baseline.Group{{Name: "sudo", GID: 27}, {Name: "games", GID: 0}, {Name: "users", GID: 100}}
	if f := one(t, Diff(withAccts(nil, base, nil), withAccts(nil, zero, nil))); f.Severity != model.SevCritical {
		t.Fatalf("%+v", f)
	}
}

// Group privilege follows the number: a new group that shares a privileged
// group's gid puts its members in that group.
func TestDiffGroups_NewGroupWithPrivilegedGID(t *testing.T) {
	base := []baseline.Group{{Name: "sudo", GID: 27}}
	for _, g := range []baseline.Group{{Name: "evil", GID: 0}, {Name: "evil", GID: 27, Members: []string{"mallory"}}} {
		f := one(t, Diff(withAccts(nil, base, nil), withAccts(nil, append([]baseline.Group{g}, base...), nil)))
		if f.Kind != model.KindAdded || f.Severity != model.SevCritical {
			t.Fatalf("%+v", f)
		}
	}
}

func TestDiffAccounts_NewAccountInPrivilegedGroup(t *testing.T) {
	groups := []baseline.Group{{Name: "sudo", GID: 27}}
	eve := baseline.Account{Name: "eve", UID: 1001, GID: 27}
	f := one(t, Diff(withAccts([]baseline.Account{}, groups, nil), withAccts([]baseline.Account{eve}, groups, nil)))
	if f.Severity != model.SevCritical || !strings.Contains(f.Detail, "sudo") {
		t.Fatalf("%+v", f)
	}
}
