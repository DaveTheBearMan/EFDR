package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/dnsguard"
	"xdr/internal/guard"
	"xdr/internal/install"
	"xdr/internal/pki"
	"xdr/internal/rules"
	"xdr/internal/sshgate"
)

// dnsBackup is where the agent's DNS pin keeps the resolver files it
// replaced (its state directory's dns-orig).
const dnsBackup = "/var/lib/xdr/dns-orig"

// layout and runner are what install and ensure act on; tests replace them.
var (
	layout = install.DefaultLayout()
	runner = install.Runner(install.ExecRunner)
)

// installCmd is `xdr install [--config FILE]`: this binary becomes the
// installed one (three copies, pinned hash, launch points).
func installCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("install", stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, "usage: xdr install [--config FILE]\n\n"+
			"Upgrading with xdr install while the agent runs (or a controller reinstall to a box\n"+
			"whose agent is alive) rewrites files under the agent's tamper watch: it is reported\n"+
			"as tamper and the installing process tree is killed, unless a pause token is active\n"+
			"(xdr breakglass <pause token>): pause it first.\n\n")
		fs.PrintDefaults()
	}
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

// uninstallCmd is `xdr uninstall --token T [--dir FLEETDIR]`: for a dead
// agent. With the agent alive (its gate socket answers) it refuses: the
// token goes to the agent with `xdr breakglass`, and the agent uninstalls
// itself, so nothing here races its self-healing. The token is checked here, with the fleet bundle's rule key and
// this box's certificate name; it never reaches a shell. There is no ledger
// here: a token is not marked used, so within its window it can be replayed
// by anyone who holds it and is root on this box (the install is gone after
// the first use, which also removes the certificate that names the host).
func uninstallCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("uninstall", stderr)
	tok := fs.String("token", "", "an uninstall break-glass token for this host")
	dir := fs.String("dir", filepath.Join(layout.Root, layout.FleetDir), "the fleet bundle (rules.pub, host.pem)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *tok == "" {
		fmt.Fprint(stderr, "xdr uninstall: --token is required\n")
		return errUsage
	}
	if c, err := net.DialTimeout("unix", gateSocket, time.Second); err == nil {
		c.Close()
		return errors.New("the agent is running; use `xdr breakglass <token>` instead (the agent uninstalls itself)")
	}
	pub, err := rules.LoadPublic(filepath.Join(*dir, "rules.pub"))
	if err != nil {
		return err
	}
	host, err := pki.HostName(filepath.Join(*dir, "host.pem"))
	if err != nil {
		return err
	}
	t, err := breakglass.Parse(*tok, pub)
	if err == nil && t.Action != "uninstall" {
		err = fmt.Errorf("token is for %s, not uninstall", t.Action)
	}
	if err == nil {
		err = t.Valid(host, time.Now())
	}
	if err != nil {
		return err
	}
	// The gate's binary is about to go; a gate that cannot run refuses
	// every session.
	root := layout.Root
	if root == "" {
		root = "/"
	}
	if _, err := sshgate.ReleasePAM(root); err != nil {
		return fmt.Errorf("the ssh gate stays in PAM: %w", err)
	}
	// sshd_config back to the baseline's, checked and reloaded; on a
	// failure the render stays (sshd works with it) and the uninstall goes on.
	if changed, err := sshgate.ReleaseSSHD(root, runner); err != nil {
		fmt.Fprintln(stderr, "xdr uninstall:", err)
	} else if changed {
		fmt.Fprintln(stdout, "restored /etc/ssh/sshd_config")
	}
	// The resolver files the agent's DNS pin replaced go back first: with
	// the agent and its stub gone the box must still resolve.
	restored, err := dnsguard.Restore(root, filepath.Join(root, dnsBackup))
	for _, p := range restored {
		fmt.Fprintln(stdout, "restored", p)
	}
	if err != nil {
		return fmt.Errorf("the resolver files were not restored: %w", err)
	}
	if err := install.Uninstall(layout, runner); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "uninstalled")
	return nil
}
