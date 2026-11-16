package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/config"
	"xdr/internal/console"
	"xdr/internal/controller"
	"xdr/internal/incident"
	"xdr/internal/pki"
	"xdr/internal/rules"
)

// controllerCmd is `xdr controller`: the jump-box side of the fleet.
func controllerCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, "xdr controller: init|enroll|run|disable-host|sign-config|console-password|mint-breakglass|approve-session|kill-session|approve-user|rotate|creds|reinstall\n")
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
	case "run":
		fs := flags("controller run", stderr)
		dir := fs.String("dir", "", "controller directory")
		cfgPath := fs.String("config", "", "controller config (default DIR/controller.json)")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" {
			fmt.Fprint(stderr, "xdr controller run: --dir is required\n")
			return errUsage
		}
		if *cfgPath == "" {
			*cfgPath = filepath.Join(*dir, "controller.json")
		}
		return controllerRun(*dir, *cfgPath, stdout)
	case "disable-host":
		fs := flags("controller disable-host", stderr)
		dir := fs.String("dir", "", "controller directory")
		host := fs.String("host", "", "enrolled host to take write access from")
		endpoint := fs.String("endpoint", "", "etcd address (default: listen in DIR/controller.json)")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" || *host == "" {
			fmt.Fprint(stderr, "xdr controller disable-host: --dir and --host are required\n")
			return errUsage
		}
		hosts, err := pki.Hosts(*dir)
		if err != nil {
			return err
		}
		if !slices.Contains(hosts, *host) {
			return fmt.Errorf("%s is not enrolled", *host)
		}
		key, err := rules.LoadPrivate(filepath.Join(*dir, "rules.key"))
		if err != nil {
			return err
		}
		c, err := rootClient(*dir, *endpoint)
		if err != nil {
			return err
		}
		defer c.Close()
		ctl, err := controller.New(*dir, c, rules.Guard{}, key, nil)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ctl.DisableHost(ctx, *host, "by the operator"); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "disabled %s: it can no longer propose, report or send heartbeats\n", *host)
	case "approve-session", "kill-session", "approve-user":
		return orderCmd(sub, rest, stdout, stderr)
	case "rotate":
		return rotateCmd(rest, stdout, stderr)
	case "reinstall":
		fs := flags("controller reinstall", stderr)
		dir := fs.String("dir", "", "controller directory")
		host := fs.String("host", "", "enrolled host listed under reinstall.hosts in controller.json")
		binary := fs.String("binary", "", "binary to put on the box (default: this one)")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" || *host == "" {
			fmt.Fprint(stderr, "xdr controller reinstall: --dir and --host are required\n")
			return errUsage
		}
		cfg, err := controller.LoadConfig(filepath.Join(*dir, "controller.json"))
		if err != nil {
			return err
		}
		if cfg.Reinstall == nil {
			return fmt.Errorf("controller.json has no reinstall section")
		}
		if *binary == "" {
			if *binary, err = os.Executable(); err != nil {
				return err
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		ssh := controller.ExecSSH{Key: cfg.Reinstall.Key, User: cfg.Reinstall.User}
		if err := controller.Reinstall(ctx, *dir, cfg, *host, ssh, *binary); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "reinstalled %s\n", *host)
	case "creds":
		return credsCmd(rest, stdout, stderr)
	case "console-password":
		fs := flags("controller console-password", stderr)
		dir := fs.String("dir", "", "controller directory")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" {
			fmt.Fprint(stderr, "xdr controller console-password: --dir is required (the password is read from stdin)\n")
			return errUsage
		}
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1025))
		if err != nil {
			return err
		}
		pw := strings.TrimRight(string(b), "\r\n")
		if len(pw) > 1024 {
			return fmt.Errorf("the password is over 1024 characters")
		}
		if err := console.SetPassword(*dir, pw); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "console password set in %s/console.json\n", *dir)
	case "mint-breakglass":
		return mintCmd(rest, stdout, stderr)
	case "sign-config":
		fs := flags("controller sign-config", stderr)
		dir := fs.String("dir", "", "controller directory")
		if err := parse(fs, rest); err != nil {
			return err
		}
		if *dir == "" || fs.NArg() != 1 {
			fmt.Fprint(stderr, "xdr controller sign-config: --dir and one agent config are required\n")
			return errUsage
		}
		path := fs.Arg(0)
		// The bytes signed are the bytes validated.
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := config.Parse(data); err != nil {
			return fmt.Errorf("%s: %w; not signed", path, err)
		}
		key, err := rules.LoadPrivate(filepath.Join(*dir, "rules.key"))
		if err != nil {
			return err
		}
		if err := os.WriteFile(path+".sig", config.Signature(data, key), 0o644); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "signed %s: copy %s.sig next to it\n", path, path)
	default:
		fmt.Fprintf(stderr, "xdr controller: unknown subcommand %q\n", sub)
		return errUsage
	}
	return nil
}

// controllerRun is `xdr controller run`: etcd, then promotion, intake and
// heartbeat watch until SIGINT or SIGTERM. Every incident it logs is
// printed, the host first.
func controllerRun(dir, cfgPath string, stdout io.Writer) error {
	cfg, err := controller.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	guard, err := cfg.Guard()
	if err != nil {
		return err
	}
	key, err := rules.LoadPrivate(filepath.Join(dir, "rules.key"))
	if err != nil {
		return err
	}
	hosts, err := pki.Hosts(dir)
	if err != nil {
		return err
	}
	e, c, err := controller.StartEtcd(dir, cfg.Listen)
	if err != nil {
		return err
	}
	defer e.Close()
	defer c.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	bctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = controller.Bootstrap(bctx, c, hosts)
	cancel()
	if err != nil {
		return err
	}
	logPath := filepath.Join(dir, "incidents.jsonl")
	var view *console.State
	if cfg.Console != nil {
		if view, err = console.NewState(dir, time.Now); err != nil {
			return err
		}
		if err := view.LoadLog(logPath); err != nil {
			fmt.Fprintf(stdout, "console: reading the incident log: %v\n", err)
		}
	}
	log, err := incident.Open(logPath, time.Minute)
	if err != nil {
		return err
	}
	defer log.Close()
	log.OnWrite = func(in incident.Incident) {
		fmt.Fprint(stdout, printable(in.Host, false)+" ")
		printIncidents(stdout, []incident.Incident{in})
		if view != nil {
			view.Feed(in)
		}
	}
	ctl, err := controller.New(dir, c, guard, key, log)
	if err != nil {
		return err
	}
	if cfg.Reinstall != nil {
		if self, err := os.Executable(); err == nil {
			ctl.EnableReinstall(cfg, controller.ExecSSH{Key: cfg.Reinstall.Key, User: cfg.Reinstall.User}, self)
		}
	}
	fmt.Fprintf(stdout, "controller: listening on %s, %d hosts enrolled, rules version %d\n", cfg.Listen, len(hosts), ctl.Current().Version)
	if view != nil {
		startConsole(ctx, dir, cfg, c, key, ctl, view, stdout)
	}
	return ctl.Run(ctx)
}

// rootClient is an etcd client as root, to endpoint or to the listen
// address in dir's controller.json.
func rootClient(dir, endpoint string) (*clientv3.Client, error) {
	if endpoint == "" {
		cfg, err := controller.LoadConfig(filepath.Join(dir, "controller.json"))
		if err != nil {
			return nil, err
		}
		endpoint = cfg.Listen
	}
	tc, err := pki.ClientTLS(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "root.pem"), filepath.Join(dir, "root-key.pem"))
	if err != nil {
		return nil, err
	}
	return clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, TLS: tc, DialTimeout: 5 * time.Second})
}

// rulesCmd is `xdr rules list|revoke`: the signed set, from the jump box.
func rulesCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "list" && args[0] != "revoke" {
		fmt.Fprint(stderr, "xdr rules: list|revoke\n")
		return errUsage
	}
	sub := args[0]
	fs := flags("rules "+sub, stderr)
	dir := fs.String("dir", "", "controller directory")
	endpoint := fs.String("endpoint", "", "etcd address (default: listen in DIR/controller.json)")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	if *dir == "" {
		fmt.Fprintf(stderr, "xdr rules %s: --dir is required\n", sub)
		return errUsage
	}
	if sub == "revoke" && fs.NArg() != 1 {
		fmt.Fprint(stderr, "xdr rules revoke: give one rule id\n")
		return errUsage
	}
	key, err := rules.LoadPrivate(filepath.Join(*dir, "rules.key"))
	if err != nil {
		return err
	}
	c, err := rootClient(*dir, *endpoint)
	if err != nil {
		return err
	}
	defer c.Close()
	ctl, err := controller.New(*dir, c, rules.Guard{}, key, nil)
	if err != nil {
		return err
	}
	if sub == "revoke" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ctl.Revoke(ctx, fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "revoked %s: version %d\n", fs.Arg(0), ctl.Current().Version)
		return nil
	}
	s := ctl.Current()
	fmt.Fprintf(stdout, "version %d, %d rules\n", s.Version, len(s.Rules))
	for _, r := range s.Rules {
		match := printable(strings.TrimPrefix(r.Key(), r.Kind+":"), false)
		if r.Kind == "cron" {
			match = strconv.QuoteToASCII(r.Command) // it has spaces
		}
		fmt.Fprintf(stdout, "%s %s %s %s %s %s\n", r.ID, r.Kind, match, printable(r.From, false),
			r.Seen.UTC().Format(time.RFC3339), printable(r.Exe, false))
	}
	return nil
}

// startConsole serves the web console in the background. A console that
// cannot start (no password set, the address taken) is said so and the
// controller goes on without it.
func startConsole(ctx context.Context, dir string, cfg *controller.Config, c *clientv3.Client, key ed25519.PrivateKey, ctl *controller.Controller, view *console.State, stdout io.Writer) {
	if _, err := os.Stat(filepath.Join(dir, "console.json")); err != nil {
		fmt.Fprintln(stdout, "console: not started: no password set (run `xdr controller console-password --dir "+dir+"`)")
		return
	}
	l, err := net.Listen("tcp", cfg.Console.Listen)
	if err != nil {
		fmt.Fprintf(stdout, "console: not started: %v\n", err)
		return
	}
	act := &console.Actions{Dir: dir, Client: func() (*clientv3.Client, error) { return c, nil }, Cfg: cfg, Key: key, State: view, Now: time.Now}
	srv := console.NewServer(dir, func() console.View { return view.View(ctl.Hosts(), ctl.Current()) }, act, time.Now, os.Stderr)
	srv.Audit = ctl.Record
	fmt.Fprintf(stdout, "console: https://%s\n", l.Addr())
	go func() {
		if err := console.Serve(ctx, l, dir, srv); err != nil {
			fmt.Fprintf(stdout, "console: stopped: %v\n", err)
		}
	}()
}
