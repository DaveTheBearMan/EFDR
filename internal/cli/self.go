package cli

import (
	"fmt"
	"io"
	"os"

	"xdr/internal/install"
)

// layout and runner are what install and ensure act on; tests replace them.
var (
	layout = install.DefaultLayout()
	runner = install.Runner(install.ExecRunner)
)

// installCmd is `xdr install [--config FILE]`: this binary becomes the
// installed one (three copies, pinned hash, launch points).
func installCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("install", stderr)
	cfg := fs.String("config", layout.Config, "the agent's config (agent.json, with its .sig and the fleet bundle beside it)")
	if err := parse(fs, args); err != nil {
		return err
	}
	l := layout
	l.Config = *cfg
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	rep, err := install.Install(l, runner, exe)
	for _, p := range rep.Wrote {
		fmt.Fprintln(stdout, "wrote", p)
	}
	if err != nil {
		return err
	}
	if len(rep.Wrote) == 0 {
		fmt.Fprintln(stdout, "already installed; nothing changed")
	}
	return nil
}

// ensureCmd is `xdr ensure`: what every launch point runs. Exit 0: nothing
// was wrong; 3: something was put back or started; 1: it could not.
func ensureCmd(stdout, stderr io.Writer) (int, error) {
	rep, err := install.Ensure(layout, runner)
	for _, p := range rep.Restored {
		fmt.Fprintln(stdout, "restored", p)
	}
	for _, u := range rep.Started {
		fmt.Fprintln(stdout, "started", u)
	}
	switch {
	case err != nil:
		return 0, err
	case len(rep.Restored)+len(rep.Started) > 0:
		return 3, nil
	}
	return 0, nil
}

