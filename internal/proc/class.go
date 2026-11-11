package proc

import (
	"path"
	"slices"
	"strings"
)

var (
	shells   = []string{"sh", "bash", "dash", "zsh", "ksh", "ash", "tcsh", "csh", "fish", "busybox"}
	interps  = []string{"node", "nodejs", "gawk"}
	interpsP = []string{"python", "perl", "ruby", "php", "lua"}
	nettools = []string{"nc", "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet", "openssl"}
)

// Class sorts a program by what it runs: "shell", "interp", "nettool" or
// "". It goes by the base name of exe, and of comm when there is no exe.
func Class(exe, comm string) string {
	name := comm
	if exe != "" {
		name = path.Base(exe)
	}
	switch {
	case slices.Contains(shells, name):
		return "shell"
	case slices.Contains(nettools, name):
		return "nettool"
	case slices.Contains(interps, name):
		return "interp"
	}
	for _, pre := range interpsP {
		if strings.HasPrefix(name, pre) {
			return "interp"
		}
	}
	return ""
}
