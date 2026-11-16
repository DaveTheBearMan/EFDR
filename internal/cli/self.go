package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"xdr/internal/guard"
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

// guardCmd is `xdr guard --watch UNIT [--every 1s]`: a watcher that keeps the
// agent, the launch points and the other guard alive.
func guardCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("guard", stderr)
	watch := fs.String("watch", "", "the other guard's unit (xdr-guard-a.service or xdr-guard-b.service)")
	every := fs.Duration("every", time.Second, "how often to look")
	if err := parse(fs, args); err != nil {
		return err
	}
	if !slices.Contains(install.Units, *watch) || !strings.HasPrefix(*watch, "xdr-guard-") {
		fmt.Fprint(stderr, "xdr guard: --watch must be xdr-guard-a.service or xdr-guard-b.service\n")
		return errUsage
	}
	if *every < 100*time.Millisecond {
		return fmt.Errorf("--every %s is under 100ms", *every)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	guard.Run(ctx, layout, runner, *watch, *every, func(s string) { fmt.Fprintln(stderr, "guard:", s) })
	return nil
}
