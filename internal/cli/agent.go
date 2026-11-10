package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"xdr/internal/agent"
	"xdr/internal/config"
	"xdr/internal/fw"
	"xdr/internal/incident"
	"xdr/internal/proc"
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

// agentCmd is `xdr agent`: it runs until it is stopped, printing each
// incident as it is logged.
func agentCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("agent", stderr)
	path := fs.String("config", "", "deployment config (agent.json)")
	var layers multi
	fs.Var(&layers, "baseline", "baseline layer over the embedded one; repeat to compose in order")
	mode := fs.String("sensor", "auto", "event source: auto, ebpf, proc or none")
	log := fs.String("log", defaultIncidents, "incident log")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *path == "" {
		fmt.Fprint(stderr, "xdr agent: --config is required\n")
		return errUsage
	}
	if !slices.Contains([]string{"auto", "ebpf", "proc", "none"}, *mode) {
		fmt.Fprintf(stderr, "xdr agent: unknown sensor %q\n", *mode)
		return errUsage
	}
	return agent.Run(context.Background(), agent.Options{
		ConfigPath: *path,
		Baselines:  layers,
		Sensor:     *mode,
		LogPath:    *log,
		Stderr:     stderr,
		OnIncident: func(in incident.Incident) { printIncidents(stdout, []incident.Incident{in}) },
	})
}

// listenersCmd is `xdr listeners`: what listens on this box now and is not
// a scored port, as the value of the config's "listeners". Loopback ones
// are listed too, so that they can be silenced.
func listenersCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("listeners", stderr)
	path := fs.String("config", "", "deployment config (agent.json): its scored ports are left out")
	if err := parse(fs, args); err != nil {
		return err
	}
	var scored []config.Port
	if *path != "" {
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		scored = c.Scored
	}
	s, err := proc.Read("/proc")
	if err != nil {
		return err
	}
	out := []config.Listener{}
	for _, p := range s.Procs {
		for _, sock := range s.Sockets(p) {
			l := config.Listener{Proto: sock.Proto, Port: sock.Local.Port(), Exe: p.Exe}
			if !sock.Listen || l.Proto != "tcp" && l.Proto != "udp" || l.Exe == "" ||
				slices.Contains(scored, config.Port{Proto: l.Proto, Port: l.Port}) || slices.Contains(out, l) {
				continue
			}
			out = append(out, l)
		}
	}
	slices.SortFunc(out, func(x, y config.Listener) int {
		return cmp.Or(cmp.Compare(x.Proto, y.Proto), cmp.Compare(x.Port, y.Port), cmp.Compare(x.Exe, y.Exe))
	})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
