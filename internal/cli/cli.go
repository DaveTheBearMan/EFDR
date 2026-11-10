// Package cli implements the xdr command-line interface.
package cli

import (
	"fmt"
	"io"
)

// Version is set at build time with -ldflags "-X xdr/internal/cli.Version=...".
var Version = "dev"

const usage = `usage: xdr <command> [flags]

commands:
  version   print the xdr version
`

// Run executes the xdr command line and returns the process exit code:
// 0 ok / no findings, 1 findings present, 2 usage or runtime error.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "xdr %s\n", Version)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
		return 2
	}
}
