package fleet

import "time"

// Tune shortens the client's timings for tests.
func Tune(c *Client, ttl int64, beatEvery, unreachableAfter time.Duration) {
	c.ttl, c.beatEvery, c.unreachableAfter = ttl, beatEvery, unreachableAfter
	c.maxBackoff = 500 * time.Millisecond
}
