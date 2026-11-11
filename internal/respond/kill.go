// Package respond acts on a detection: it decides whether the process
// dies, and kills it with everything it started.
package respond

import (
	"errors"
	"os"
	"slices"

	"golang.org/x/sys/unix"

	"xdr/internal/detect"
	"xdr/internal/proc"
)

// Decide says what happens to the process a detection names: "kill",
// "held" (it would die, but it is a scored service) or "alert".
func Decide(d detect.Detection, s *proc.Snapshot, p *detect.Policy) string {
	pr := s.Procs[d.PID]
	switch {
	case d.NoKill || pr == nil || pr.Start != d.Start:
		return "alert"
	case p.Guarded(s, pr):
		return "held"
	case d.Kind == "revshell-stdio" || d.Kind == "service-shell":
		return "kill"
	case p.IsGray(s, pr):
		return "alert"
	case p.Baseline(pr) && detect.Class(pr) == "":
		return "alert"
	}
	return "kill"
}

// ErrGone means there was nothing to kill.
var ErrGone = errors.New("process gone or pid reused")

// ErrSpared means the process is one KillTree never kills: init, a kernel
// thread, this process or one protect names.
var ErrSpared = errors.New("process is protected")

// readProcs reads the process table; tests replace it.
var readProcs = proc.Read

// maxPasses bounds the search for processes forked while the tree was
// being stopped. Each pass stops everything it sees, and a stopped
// process cannot fork, so the search ends on its own long before this.
const maxPasses = 16

// KillTree kills the process pid that started at start, and everything
// it started. Init, kernel threads, this process and whatever protect
// names are left alone, each with its own descendants; ancestors are
// never touched. It returns the pids killed, parents first, and
// ErrSpared when pid itself is spared.
//
// The tree is stopped before it is killed, so that nothing in it can fork
// its way out, and every signal goes through a pidfd checked against the
// start time, so a recycled pid is never hit.
func KillTree(procRoot string, pid int, start uint64, protect func(*proc.Proc) bool) (killed []int, err error) {
	self := os.Getpid()
	spared := func(pr *proc.Proc) bool {
		return pr.PID == 1 || pr.Kernel || pr.PID == self || protect != nil && protect(pr)
	}
	fds := map[int]int{} // target pid → pidfd
	defer func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}()
	stop := func(pr *proc.Proc) {
		fd, err := unix.PidfdOpen(pr.PID, 0)
		if err != nil {
			return
		}
		// The pidfd pins whatever has the pid now; make sure that is
		// still the process the snapshot saw.
		cur, err := proc.ReadOne(procRoot, pr.PID)
		if err != nil || cur.Start != pr.Start || unix.PidfdSendSignal(fd, unix.SIGSTOP, nil, 0) != nil {
			unix.Close(fd)
			return
		}
		fds[pr.PID] = fd
		killed = append(killed, pr.PID)
	}

	var readErr error
	for pass := 0; pass < maxPasses; pass++ {
		s, err := readProcs(procRoot)
		if err != nil {
			if pass == 0 {
				return nil, err
			}
			// What is stopped already still dies below.
			readErr = err
			break
		}
		root := s.Procs[pid]
		if root == nil || root.Start != start {
			if pass == 0 {
				return nil, ErrGone
			}
			break
		}
		if pass == 0 && spared(root) {
			return nil, ErrSpared
		}
		kids := map[int][]*proc.Proc{}
		for _, pr := range s.Procs {
			kids[pr.PPID] = append(kids[pr.PPID], pr)
		}
		before := len(killed)
		seen := map[int]bool{}
		for queue := []*proc.Proc{root}; len(queue) > 0; queue = queue[1:] {
			pr := queue[0]
			if seen[pr.PID] || spared(pr) {
				continue
			}
			seen[pr.PID] = true
			if _, held := fds[pr.PID]; !held {
				stop(pr)
			}
			next := kids[pr.PID]
			slices.SortFunc(next, func(a, b *proc.Proc) int { return a.PID - b.PID })
			queue = append(queue, next...)
		}
		if len(killed) == before {
			break
		}
	}
	// Every stopped process gets its SIGKILL, even after one fails.
	for _, p := range killed {
		if err := unix.PidfdSendSignal(fds[p], unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) && readErr == nil {
			readErr = err
		}
	}
	return killed, readErr
}
