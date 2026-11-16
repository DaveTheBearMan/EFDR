package collect

import (
	"io/fs"
	"syscall"
)

// HashCache keeps the hashes one walk took, so the next walk reuses the
// hash of a file whose size, mtime, ctime, device and inode are unchanged
// (ctime cannot be set back by a user, as mtime can). It is for the fast
// scan, which walks the same directories every few minutes; one walk uses
// it at a time.
type HashCache struct {
	m    map[string]cachedHash
	seen map[string]bool
}

type cachedHash struct {
	stamp   stamp
	content bool // Content was wanted
	sha     string
	data    []byte
}

type stamp struct {
	size, mtime, ctime int64
	dev, ino           uint64
}

// NewHashCache is an empty cache.
func NewHashCache() *HashCache { return &HashCache{m: map[string]cachedHash{}} }

// Len is how many files the cache holds.
func (c *HashCache) Len() int { return len(c.m) }

func stampOf(info fs.FileInfo) (stamp, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return stamp{}, false
	}
	return stamp{size: info.Size(), mtime: st.Mtim.Nano(), ctime: st.Ctim.Nano(), dev: uint64(st.Dev), ino: st.Ino}, true
}

func (c *HashCache) start() { c.seen = map[string]bool{} }

// get is the cached hash of rel, when its stamp still matches.
func (c *HashCache) get(rel string, info fs.FileInfo, content bool) (string, []byte, bool) {
	s, ok := stampOf(info)
	if !ok {
		return "", nil, false
	}
	e, ok := c.m[rel]
	if !ok || e.stamp != s || e.content != content {
		return "", nil, false
	}
	c.seen[rel] = true
	return e.sha, e.data, true
}

func (c *HashCache) put(rel string, info fs.FileInfo, content bool, sha string, data []byte) {
	if s, ok := stampOf(info); ok {
		c.m[rel] = cachedHash{stamp: s, content: content, sha: sha, data: data}
		c.seen[rel] = true
	}
}

// finish drops what this walk did not see.
func (c *HashCache) finish() {
	for k := range c.m {
		if !c.seen[k] {
			delete(c.m, k)
		}
	}
	c.seen = nil
}

// lookup and store are get and put on a cache that may be nil.
func (c *HashCache) lookup(rel string, info fs.FileInfo, content bool) (string, []byte, bool) {
	if c == nil {
		return "", nil, false
	}
	return c.get(rel, info, content)
}

func (c *HashCache) store(rel string, info fs.FileInfo, content bool, sha string, data []byte) {
	if c != nil {
		c.put(rel, info, content, sha, data)
	}
}
