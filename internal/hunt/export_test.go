package hunt

// SetMountinfo points the search at a fake mount table.
func SetMountinfo(p string) (restore func()) {
	old := mountinfo
	mountinfo = p
	return func() { mountinfo = old }
}
