package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openDirNoFollow opens the directory dir under root one component at a
// time, never following a symlink: a user who owns a directory on the way
// cannot redirect what the agent does (as root) beside it. The caller
// closes the descriptor.
func openDirNoFollow(root, dir string) (int, error) {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, comp := range strings.Split(strings.Trim(filepath.Clean(dir), "/"), "/") {
		if comp == "" || comp == "." {
			continue
		}
		if comp == ".." {
			unix.Close(fd)
			return -1, errors.New("a .. in the path")
		}
		next, err := unix.Openat(fd, comp, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("%s: %w", comp, err)
		}
		fd = next
	}
	return fd, nil
}
