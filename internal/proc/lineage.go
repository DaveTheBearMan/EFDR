package proc

import (
	"path"
	"sort"
	"strings"
)

// Descendants lists every process below pid: its children first, then theirs.
func (s *Snapshot) Descendants(pid int) []int {
	children := map[int][]int{}
	for _, p := range s.Procs {
		children[p.PPID] = append(children[p.PPID], p.PID)
	}
	seen := map[int]bool{pid: true}
	var out []int
	for queue := []int{pid}; len(queue) > 0; queue = queue[1:] {
		next := children[queue[0]]
		sort.Ints(next)
		for _, c := range next {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

// Chain is the process and its ancestors, itself first, up to pid 1. It
// stops at a parent that is missing or already in the chain.
func (s *Snapshot) Chain(pid int) []*Proc {
	var chain []*Proc
	seen := map[int]bool{}
	for len(chain) < maxChain {
		p := s.Procs[pid]
		if p == nil || seen[pid] {
			break
		}
		seen[pid] = true
		chain = append(chain, p)
		pid = p.PPID
	}
	return chain
}

// Container is the short id of the container a cgroup path names: the first
// 12 characters of a 64-character hex id, or "" when there is none.
func Container(cgroup string) string {
	isHex := func(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }
	run := 0
	for i := 0; i <= len(cgroup); i++ {
		if i < len(cgroup) && isHex(cgroup[i]) {
			run++
			continue
		}
		if run == 64 {
			return cgroup[i-64 : i-52]
		}
		run = 0
	}
	return ""
}

// Origin says where a process came from, given its Chain.
func Origin(chain []*Proc) string {
	if len(chain) == 0 {
		return "unknown"
	}
	if id := Container(chain[0].Cgroup); id != "" {
		return "container:" + id
	}
	for _, comm := range []map[string]bool{{"sshd": true, "sshd-session": true}, {"cron": true, "atd": true}} {
		for _, p := range chain {
			if comm[p.Comm] {
				if comm["sshd"] {
					return "ssh"
				}
				return "cron"
			}
		}
	}
	if unit := path.Base(chain[0].Cgroup); strings.HasSuffix(unit, ".service") || strings.HasSuffix(unit, ".scope") {
		return "unit:" + unit
	}
	return "unknown"
}
