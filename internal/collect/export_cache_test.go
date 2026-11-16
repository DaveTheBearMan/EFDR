package collect

// poison replaces a cached hash, to tell a reused hash from a new one.
func (c *HashCache) poison(rel, sha string) {
	e := c.m[rel]
	e.sha = sha
	c.m[rel] = e
}
