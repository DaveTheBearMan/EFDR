package collect

import (
	"path/filepath"
	"sort"
	"strings"
)

// Modules lists loaded kernel modules from root/proc/modules, sorted.
// It returns nil when the file is absent (e.g. an offline image).
func Modules(root string) []string {
	data, err := ReadFile(filepath.Join(root, "proc/modules"), maxDB)
	if err != nil {
		return nil
	}
	return parseModules(data)
}

func parseModules(data []byte) []string {
	mods := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 {
			mods = append(mods, fields[0])
		}
	}
	sort.Strings(mods)
	return mods
}
