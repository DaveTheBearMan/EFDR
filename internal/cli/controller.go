package cli

import (
	"fmt"
	"io"

	"xdr/internal/pki"
)

// controllerCmd is `xdr controller`: the jump-box side of the fleet.
func controllerCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, "xdr controller: init|enroll\n")
		return errUsage
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "init":
		fs := flags("controller init", stderr)
		dir := fs.String("dir", "", "controller directory to create")
		var names multi
		fs.Var(&names, "name", "address or DNS name agents reach the controller at; repeat")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" || len(names) == 0 {
			fmt.Fprint(stderr, "xdr controller init: --dir and --name are required\n")
			return errUsage
		}
		if err := pki.Init(*dir, names); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "initialised %s\n", *dir)
	case "enroll":
		fs := flags("controller enroll", stderr)
		dir := fs.String("dir", "", "controller directory")
		host := fs.String("host", "", "host name, as in its agent config")
		out := fs.String("out", "", "directory to write the host's bundle to (must not exist)")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" || *host == "" || *out == "" {
			fmt.Fprint(stderr, "xdr controller enroll: --dir, --host and --out are required\n")
			return errUsage
		}
		if err := pki.Enroll(*dir, *host, *out); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "enrolled %s: copy %s to /etc/xdr/fleet on it\n", *host, *out)
	default:
		fmt.Fprintf(stderr, "xdr controller: unknown subcommand %q\n", sub)
		return errUsage
	}
	return nil
}
