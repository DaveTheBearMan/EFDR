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
	bob := baseline.Account{Name: "bob", UID: 1003, Shell: "/bin/bash"}
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
