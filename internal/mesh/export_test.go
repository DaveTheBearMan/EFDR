package mesh

import "time"

// Tune shortens the mesh's clocks for tests.
func Tune(m *Mesh, beat, silent time.Duration) { m.beatEvery, m.silentAfter = beat, silent }
