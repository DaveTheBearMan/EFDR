package proc

import (
	"reflect"
	"strings"
	"testing"

	"xdr/internal/testfs"
)

func pids(chain []*Proc) (out []int) {
	for _, p := range chain {
		out = append(out, p.PID)
	}
	return out
}

func TestChain_CycleAndMissingParent(t *testing.T) {
	root := testfs.Root(t)
	mkproc(t, root, 1, 0, "systemd")
	mkproc(t, root, 5, 1, "sshd")
	mkproc(t, root, 6, 5, "bash")
	mkproc(t, root, 10, 11, "a")
	mkproc(t, root, 11, 10, "b")
	mkproc(t, root, 20, 19, "orphan")
	s := snap(t, root)
	for pid, want := range map[int][]int{
		6:  {6, 5, 1},
		10: {10, 11},
		20: {20},
		99: nil,
	} {
		if got := pids(s.Chain(pid)); !reflect.DeepEqual(got, want) {
			t.Errorf("Chain(%d) = %v, want %v", pid, got, want)
		}
	}
}

func TestChain_AtMost64(t *testing.T) {
	s := &Snapshot{Procs: map[int]*Proc{}}
	for pid := 1; pid <= 200; pid++ {
		s.Procs[pid] = &Proc{PID: pid, PPID: pid - 1}
	}
	if got := s.Chain(200); len(got) != 64 || got[0].PID != 200 {
		t.Fatalf("chain of %d", len(got))
	}
}

func TestDescendants(t *testing.T) {
	s := &Snapshot{Procs: map[int]*Proc{}}
	for pid, ppid := range map[int]int{1: 0, 10: 1, 11: 10, 12: 10, 13: 11, 14: 13, 20: 1, 30: 31, 31: 30} {
		s.Procs[pid] = &Proc{PID: pid, PPID: ppid}
	}
	if got := s.Descendants(10); !reflect.DeepEqual(got, []int{11, 12, 13, 14}) {
		t.Fatalf("Descendants(10) = %v", got)
	}
	if got := s.Descendants(14); len(got) != 0 {
		t.Fatalf("Descendants(14) = %v", got)
	}
	if got := s.Descendants(30); !reflect.DeepEqual(got, []int{31}) {
		t.Fatalf("Descendants(30) = %v (cycle)", got)
	}
}

func TestContainer(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	for cgroup, want := range map[string]string{
		"/system.slice/docker-" + id + ".scope":          "0123456789ab",
		"/docker/" + id:                                  "0123456789ab",
		"/system.slice/ssh.service":                      "",
		"/docker/" + id[:63]:                             "",
		"/docker/" + id + "a":                            "",
		"/kubepods/pod1/cri-containerd-" + id + ".scope": "0123456789ab",
		"": "",
	} {
		if got := Container(cgroup); got != want {
			t.Errorf("Container(%q) = %q, want %q", cgroup, got, want)
		}
	}
}

func TestOrigin(t *testing.T) {
	id := strings.Repeat("ab", 32)
	systemd := &Proc{PID: 1, Comm: "systemd", Cgroup: "/init.scope"}
	for name, c := range map[string]struct {
		chain []*Proc
		want  string
	}{
		"container": {[]*Proc{{Comm: "sh", Cgroup: "/system.slice/docker-" + id + ".scope"}, {Comm: "sshd"}}, "container:abababababab"},
		"ssh":       {[]*Proc{{Comm: "sh", Cgroup: "/user.slice/user-0.slice/session-3.scope"}, {Comm: "bash"}, {Comm: "sshd"}, systemd}, "ssh"},
		"cron":      {[]*Proc{{Comm: "sh", Cgroup: "/system.slice/cron.service"}, {Comm: "cron"}, systemd}, "cron"},
		"atd":       {[]*Proc{{Comm: "sh", Cgroup: "/system.slice/atd.service"}, {Comm: "atd"}, systemd}, "cron"},
		"unit":      {[]*Proc{{Comm: "sh", Cgroup: "/system.slice/apache2.service"}, {Comm: "apache2"}, systemd}, "unit:apache2.service"},
		"scope":     {[]*Proc{{Comm: "sh", Cgroup: "/user.slice/user-0.slice/session-3.scope"}, systemd}, "unit:session-3.scope"},
		"unknown":   {[]*Proc{{Comm: "sh", Cgroup: "/"}, systemd}, "unknown"},
		"empty":     {nil, "unknown"},
	} {
		if got := Origin(c.chain); got != c.want {
			t.Errorf("%s: Origin = %q, want %q", name, got, c.want)
		}
	}
}
