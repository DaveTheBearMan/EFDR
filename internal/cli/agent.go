package cli

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xdr/internal/config"
	"xdr/internal/fw"
	"xdr/internal/incident"
)

// fwConfirm is the file `fw confirm` writes and `fw try` waits for.
var fwConfirm = "/run/xdr/fw-confirm"

// fwCmd is `xdr fw print|apply|try|confirm|remove`.
func fwCmd(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		fmt.Fprint(stderr, "usage: xdr fw print|apply|try|confirm|remove --config FILE [--timeout D]\n")
		return 0, errUsage
	}
	verb := args[0]
	fs := flags("fw "+verb, stderr)
	path := fs.String("config", "", "deployment config (agent.json)")
	timeout := fs.Duration("timeout", 60*time.Second, "try: how long to wait for `xdr fw confirm`")
	if err := parse(fs, args[1:]); err != nil {
		return 0, err
	}
	var rules fw.Ruleset
	switch verb {
	case "print", "apply", "try":
		if *path == "" {
			fmt.Fprintf(stderr, "xdr fw %s: --config is required\n", verb)
			return 0, errUsage
		}
		c, err := config.Load(*path)
		if err != nil {
			return 0, err
		}
		rules = fw.Build(c, time.Now())
	case "confirm", "remove":
	default:
		fmt.Fprintf(stderr, "xdr fw: unknown verb %q\n", verb)
		return 0, errUsage
	}
	switch verb {
	case "print":
		fmt.Fprint(stdout, rules.String())
		return 0, nil
	case "confirm":
		if err := os.MkdirAll(filepath.Dir(fwConfirm), 0o700); err != nil {
			return 0, err
		}
		return 0, os.WriteFile(fwConfirm, nil, 0o600)
	}

	f, err := fw.Open()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	switch verb {
	case "remove":
		return 0, f.Remove()
	case "apply":
		return 0, f.Apply(rules)
	}
	// try: a table that locks the operator out removes itself.
	if err := os.Remove(fwConfirm); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := f.Apply(rules); err != nil {
		return 0, err
	}
	fmt.Fprintf(stdout, "applied; run `xdr fw confirm` within %s to keep it\n", *timeout)
	for deadline := time.Now().Add(*timeout); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if _, err := os.Lstat(fwConfirm); err == nil {
			fmt.Fprintln(stdout, "confirmed")
			return 0, nil
		}
	}
	if err := f.Remove(); err != nil {
		return 0, fmt.Errorf("not confirmed, and removing the table failed: %w", err)
	}
	fmt.Fprintln(stdout, "reverted")
	return 1, nil
}

// defaultIncidents is where the agent keeps its incident log.
const defaultIncidents = "/var/lib/xdr/incidents.jsonl"

func incidentsCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("incidents", stderr)
	path := fs.String("file", defaultIncidents, "incident log")
	if err := parse(fs, args); err != nil {
		return err
	}
	f, err := os.Open(*path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing has happened yet
	}
	if err != nil {
		return err
	}
	defer f.Close()
	incidents, err := incident.Read(f)
	printIncidents(stdout, incidents)
	return err
}

// printIncidents writes one line per incident:
//
//	TIME SEV kind action pid=N exe → addr:port detail
//
// Everything in an incident came from the watched host, so every field is
// escaped.
func printIncidents(w io.Writer, incidents []incident.Incident) {
	for _, in := range incidents {
		fields := []string{
			in.Time.UTC().Format(time.RFC3339),
			strings.ToUpper(in.Severity.String()),
			printable(in.Kind, false),
			printable(in.Action, false),
			fmt.Sprintf("pid=%d", in.PID),
		}
		if in.Exe != "" {
			fields = append(fields, printable(in.Exe, false))
		}
		if in.Remote != nil {
			fields = append(fields, "→", printable(net.JoinHostPort(in.Remote.Addr, strconv.Itoa(int(in.Remote.Port))), false))
		}
		if in.Detail != "" {
			fields = append(fields, printable(in.Detail, false))
		}
		if in.Count > 1 {
			fields = append(fields, fmt.Sprintf("(x%d)", in.Count))
		}
		fmt.Fprintln(w, strings.Join(fields, " "))
	}
}
