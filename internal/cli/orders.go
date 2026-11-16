package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"xdr/internal/controller"
	"xdr/internal/pki"
)

var (
	sessionArg = regexp.MustCompile(`^c?[0-9]{1,10}$`)
	userArg    = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// orderCmd is `xdr controller approve-session|kill-session --host H ID`
// and `approve-user --host H NAME`: an order the host's agent obeys.
func orderCmd(sub string, rest []string, stdout, stderr io.Writer) error {
	fs := flags("controller "+sub, stderr)
	dir := fs.String("dir", "", "controller directory")
	host := fs.String("host", "", "enrolled host")
	endpoint := fs.String("endpoint", "", "etcd address (default: listen in DIR/controller.json)")
	if err := parse(fs, rest); err != nil {
		return err
	}
	if *dir == "" || *host == "" || fs.NArg() != 1 {
		fmt.Fprintf(stderr, "xdr controller %s: --dir, --host and one id or name are required\n", sub)
		return errUsage
	}
	arg := fs.Arg(0)
	kind, verdict := "session", "approve"
	switch sub {
	case "kill-session":
		verdict = "kill"
	case "approve-user":
		kind = "user"
	}
	if kind == "session" && !sessionArg.MatchString(arg) {
		return fmt.Errorf("%q is not a session id", arg)
	}
	if kind == "user" {
		if !userArg.MatchString(arg) {
			return fmt.Errorf("%q is not a user name", arg)
		}
		if err := refuseProtected(*dir, arg); err != nil {
			return err
		}
	}
	if err := enrolled(*dir, *host); err != nil {
		return err
	}
	c, err := rootClient(*dir, *endpoint)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.PutOrder(ctx, c, *host, kind, arg, orderValue(verdict, time.Now())); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s %s %s on %s\n", verdict, kind, arg, *host)
	return nil
}

// refuseProtected refuses a gray account, as the controller config lists
// them; with rotation also true, the recovery and platform accounts too.
func refuseProtected(dir, user string, rotation ...bool) error {
	cfg, err := controller.LoadConfig(filepath.Join(dir, "controller.json"))
	if err != nil {
		return err
	}
	if slices.Contains(cfg.GrayUsers, user) {
		return fmt.Errorf("refused: %s is a protected account", user)
	}
	if len(rotation) > 0 && rotation[0] && (user == cfg.Recovery || slices.Contains(cfg.Auto, user)) {
		return fmt.Errorf("refused: %s is the recovery or a platform account; it is not rotated", user)
	}
	return nil
}

func enrolled(dir, host string) error {
	hosts, err := pki.Hosts(dir)
	if err != nil {
		return err
	}
	if !slices.Contains(hosts, host) {
		return fmt.Errorf("%s is not enrolled", host)
	}
	return nil
}

// orderValue is an order's JSON: the verdict, and when it was put, so that
// an agent can tell one left over from before its boot (session ids
// restart at every boot).
func orderValue(verdict string, at time.Time) map[string]any {
	return controller.OrderValue(verdict, at, "")
}
