package hunt

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"xdr/internal/classify"
	"xdr/internal/collect"
	"xdr/internal/persist"
	"xdr/internal/proc"
)

// Hit is one indicator found. Kind is file | path | process | connection
// | unit | cron | user; a path hit is a file at a hunted path with
// another hash, a variant.
type Hit struct {
	Kind, What, Path, SHA256 string
	PID                      int
}

// Result is what a search found. Partial says which budget ran out, if
// one did; Unreadable counts files that should have been hashed and could
// not be.
type Result struct {
	Hits       []Hit
	Partial    string
	Unreadable int
}

// Budget bounds one search.
type Budget struct {
	Files  int           // entries walked
	Hashed int64         // bytes read
	Time   time.Duration // wall time
}

// DefaultBudget keeps a hunt to about a minute of one core and a bounded
// read on a competition box.
var DefaultBudget = Budget{Files: 500000, Hashed: 2 << 30, Time: 60 * time.Second}

// checkEvery is how many walked entries pass between budget checks.
const checkEvery = 256

// searcher is one search in progress.
type searcher struct {
	ctx      context.Context
	root     string
	b        Budget
	deadline time.Time
	hashed   int64
	res      Result
}

func (s *searcher) stop(why string) {
	if s.res.Partial == "" {
		s.res.Partial = why
	}
}

func (s *searcher) over() bool {
	switch {
	case s.res.Partial != "":
	case s.ctx.Err() != nil:
		s.stop("cancelled")
	case time.Now().After(s.deadline):
		s.stop("time budget")
	}
	return s.res.Partial != ""
}

// hash reads one regular file without following a final symlink or
// blocking on a special file, within the byte budget. "" when it could
// not.
func (s *searcher) hash(full string, size int64) string {
	if s.hashed+size > s.b.Hashed {
		s.stop("hash budget")
		return ""
	}
	f, err := os.OpenFile(full, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.res.Unreadable++
		}
		return ""
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	s.hashed += n
	if err != nil || n != size {
		return "" // changed under us
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Search looks for req's indicators on the box under root and in its
// process snapshot. hash gives a process's exe hash. It reads only, and
// stops at b or when ctx is done.
func Search(ctx context.Context, root string, req *Request, snap *proc.Snapshot, hash func(*proc.Proc) string, b Budget) Result {
	s := &searcher{ctx: ctx, root: filepath.Clean(root), b: b, deadline: time.Now().Add(b.Time)}
	if s.over() {
		return s.res
	}
	ioc := req.IOC
	shas := map[string]bool{}
	sizes := map[int64]bool{}
	paths := map[string]bool{}
	for _, f := range ioc.Files {
		shas[f.SHA256], sizes[f.Size] = true, true
		if f.Path != "" {
			paths[path.Clean("/"+f.Path)] = true
		}
	}
	add := func(h Hit) { s.res.Hits = append(s.res.Hits, h) }

	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for p := range paths {
			if !yield(p) {
				return
			}
		}
	}) {
		full := filepath.Join(s.root, p)
		st, err := os.Lstat(full)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if sum := s.hash(full, st.Size()); sum != "" {
			kind := "path"
			if shas[sum] {
				kind = "file"
			}
			add(Hit{Kind: kind, What: p, Path: p, SHA256: sum})
		}
	}

	if len(sizes) > 0 {
		s.walk(sizes, shas, paths, add)
	}

	if snap != nil {
		pids := slices.Sorted(func(yield func(int) bool) {
			for pid := range snap.Procs {
				if !yield(pid) {
					return
				}
			}
		})
		remotes := map[Remote]bool{}
		for _, r := range ioc.Remotes {
			r.Addr = r.Addr.Unmap()
			remotes[r] = true
		}
		for _, pid := range pids {
			p := snap.Procs[pid]
			if len(shas) > 0 && hash != nil && p.Exe != "" {
				if sum := hash(p); shas[sum] {
					add(Hit{Kind: "process", What: p.Exe, Path: p.Exe, SHA256: sum, PID: pid})
				}
			}
			if len(remotes) == 0 {
				continue
			}
			for _, k := range snap.Sockets(p) {
				r := Remote{Addr: k.Remote.Addr().Unmap(), Port: k.Remote.Port(), Proto: k.Proto}
				if remotes[r] {
					add(Hit{Kind: "connection", What: netip.AddrPortFrom(r.Addr, r.Port).String() + "/" + r.Proto, PID: pid})
				}
			}
		}
	}

	for _, u := range ioc.Units {
		// A template's name has its own "@": the hash follows the last one.
		i := strings.LastIndexByte(u, '@')
		if i <= 0 {
			continue
		}
		name, sum := u[:i], u[i+1:]
		if file, got, err := persist.UnitFile(s.root, name); err == nil && got == sum {
			add(Hit{Kind: "unit", What: name, Path: file, SHA256: sum})
		}
	}

	if len(ioc.Cron) > 0 {
		for _, f := range cronFiles(s.root) {
			b, err := collect.ReadFile(filepath.Join(s.root, f), 1<<20)
			if err != nil {
				continue
			}
			for _, c := range ioc.Cron {
				if bytes.Contains(b, []byte(c)) {
					add(Hit{Kind: "cron", What: c, Path: f})
				}
			}
		}
	}

	if len(ioc.Users) > 0 {
		if b, err := collect.ReadFile(filepath.Join(s.root, "etc/passwd"), 8<<20); err == nil {
			for _, a := range collect.ParsePasswd(bytes.NewReader(b)) {
				if !a.Bad && slices.Contains(ioc.Users, a.Name) {
					add(Hit{Kind: "user", What: a.Name, Path: "/etc/passwd"})
				}
			}
		}
	}
	return s.res
}

// walk hashes every regular file whose size is a hunted size, skipping
// the hunted paths (already checked), kernel views and container storage.
func (s *searcher) walk(sizes map[int64]bool, shas, paths map[string]bool, add func(Hit)) {
	n := 0
	filepath.WalkDir(s.root, func(full string, d fs.DirEntry, err error) error {
		if n%checkEvery == 0 && s.over() {
			return filepath.SkipAll
		}
		if n++; n > s.b.Files {
			s.stop("file budget")
			return filepath.SkipAll
		}
		if err != nil || full == s.root {
			return nil
		}
		rel := "/" + filepath.ToSlash(strings.TrimPrefix(full, s.root+string(filepath.Separator)))
		if s.root == "/" {
			rel = full
		}
		if d.IsDir() {
			if matchAny(collect.Skipped, rel) || matchAny(collect.Sealed, rel) || collect.PseudoFS(full) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || paths[rel] {
			return nil
		}
		info, err := d.Info()
		if err != nil || !sizes[info.Size()] {
			return nil
		}
		if sum := s.hash(full, info.Size()); shas[sum] {
			add(Hit{Kind: "file", What: rel, Path: rel, SHA256: sum})
		}
		if s.res.Partial != "" {
			return filepath.SkipAll
		}
		return nil
	})
}

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if classify.Match(pat, p) {
			return true
		}
	}
	return false
}

// cronFiles is every crontab under root, as box paths.
func cronFiles(root string) []string {
	var out []string
	for _, f := range persist.CronFiles {
		st, err := os.Lstat(filepath.Join(root, f))
		switch {
		case err != nil:
		case st.Mode().IsRegular():
			out = append(out, f)
		case st.IsDir():
			ents, _ := os.ReadDir(filepath.Join(root, f))
			for _, e := range ents {
				if e.Type().IsRegular() {
					out = append(out, path.Join(f, e.Name()))
				}
			}
		}
	}
	return out
}
