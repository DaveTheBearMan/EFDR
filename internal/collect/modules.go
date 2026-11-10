package collect

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Modules lists loaded kernel modules from root/proc/modules, sorted.
// It returns nil when the file is absent (e.g. an offline image).
func Modules(root string) []string {
	f, err := os.Open(filepath.Join(root, "proc/modules"))
	if err != nil {
		return nil
	}
	defer f.Close()
	mods := []string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		if fields := strings.Fields(s.Text()); len(fields) > 0 {
			mods = append(mods, fields[0])
		}
	}
	sort.Strings(mods)
	return mods
}
