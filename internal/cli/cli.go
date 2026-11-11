// Package cli implements the xdr command-line interface.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/debhash"
	"xdr/internal/diff"
	"xdr/internal/model"
)

// Version is set at build time with -ldflags "-X xdr/internal/cli.Version=...".
var Version = "dev"

const usage = `usage: xdr <command> [flags]

commands:
  capture   snapshot a host:        capture --root DIR --out FILE [--layer base|triage]
  scan      diff a host vs baseline: scan --root DIR [--baseline FILE]... [--json]
  pkglist   list installed packages: pkglist --root DIR
  pkghash   package layer from debs: pkghash --debs DIR --out FILE
  fw        host firewall:          fw print|apply|try|confirm|remove --config FILE
  incidents print the incident log: incidents [--file PATH]
  agent     watch and respond:      agent --config FILE [--baseline FILE]... [--sensor auto|ebpf|proc|none] [--log PATH]
  listeners listeners, for config:  listeners [--config FILE]
  controller jump box:              controller init --dir D --name ADDR... | enroll --dir D --host H --out DIR
  version   print the xdr version
`

// errUsage marks errors whose message is already a usage complaint.
var errUsage = errors.New("usage")

// Run executes the xdr command line and returns the process exit code:
// 0 ok / no findings, 1 findings present, 2 usage or runtime error.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var code int
	var err error
	switch cmd, rest := args[0], args[1:]; cmd {
	case "version":
		fmt.Fprintf(stdout, "xdr %s\n", Version)
	case "capture":
		err = captureCmd(rest, stderr)
	case "scan":
		code, err = scan(rest, stdout, stderr)
	case "pkglist":
		err = pkglist(rest, stdout, stderr)
	case "pkghash":
		err = pkghash(rest, stderr)
	case "fw":
		code, err = fwCmd(rest, stdout, stderr)
	case "incidents":
		err = incidentsCmd(rest, stdout, stderr)
	case "agent":
		err = agentCmd(rest, stdout, stderr)
	case "listeners":
		err = listenersCmd(rest, stdout, stderr)
	case "controller":
		err = controllerCmd(rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintf(stderr, "xdr %s: %v\n", args[0], err)
		}
		return 2
	}
	return code
}

func flags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	return nil
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func captureCmd(args []string, stderr io.Writer) error {
	fs := flags("capture", stderr)
	root := fs.String("root", "/", "root directory to snapshot")
	out := fs.String("out", "", "output baseline file")
	layer := fs.String("layer", "base", "layer to tag entries with: base or triage")
	if err := parse(fs, args); err != nil {
		return err
	}
	l := map[string]baseline.Layer{"base": baseline.LayerBase, "triage": baseline.LayerTriage}
	lv, ok := l[*layer]
	if *out == "" || !ok {
		fs.Usage()
		return errUsage
	}
	b, err := collect.Snapshot(*root)
	if err != nil {
		return err
	}
	// A baseline that could not read something vouches for less than it
	// appears to; say so while the operator can still do something about it.
	var warn []string
	for p, e := range b.Files {
		if e.Err != "" {
			warn = append(warn, p+": "+e.Err)
		}
		e.Layer = lv
		b.Files[p] = e
	}
	sort.Strings(warn)
	for _, w := range append(warn, b.Errors...) {
		fmt.Fprintf(stderr, "xdr capture: warning: %s\n", printable(w, false))
	}
	return writeBaseline(*out, b)
}

// writeBaseline writes b readable by its owner only: a baseline is a map
// of the whole box.
func writeBaseline(path string, b *baseline.Baseline) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := baseline.Save(f, b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readBaseline(path string) (*baseline.Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return baseline.Load(f)
}

func scan(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flags("scan", stderr)
	root := fs.String("root", "/", "root directory to scan")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	var files multi
	fs.Var(&files, "baseline", "baseline file; repeat to compose layers in order (default: embedded)")
	if err := parse(fs, args); err != nil {
		return 0, err
	}
	var layers []*baseline.Baseline
	for _, p := range files {
		b, err := readBaseline(p)
		if err != nil {
			return 0, err
		}
		layers = append(layers, b)
	}
	if len(layers) == 0 {
		b, err := baseline.Embedded()
		if err != nil {
			return 0, fmt.Errorf("embedded baseline: %w", err)
		}
		layers = append(layers, b)
	}
	live, err := collect.Snapshot(*root)
	if err != nil {
		return 0, err
	}
	findings := diff.Diff(baseline.Compose(layers...), live)
	if *asJSON {
		if findings == nil {
			findings = []model.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			return 0, err
		}
	} else {
		printFindings(stdout, findings)
	}
	if len(findings) > 0 {
		return 1, nil
	}
	return 0, nil
}

func printFindings(w io.Writer, findings []model.Finding) {
	for _, f := range findings {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(f.Severity.String()), f.Kind, f.Category,
			printable(f.Subject, false), printable(f.Detail, false))
		if f.Diff != "" {
			for _, line := range strings.Split(strings.TrimRight(f.Diff, "\n"), "\n") {
				fmt.Fprintf(w, "    %s\n", printable(line, true))
			}
		}
	}
}

// printable escapes everything in s that is not a printable character, so
// text taken from the scanned host cannot drive the operator's terminal or
// forge output columns. Tabs survive only where tab says so.
func printable(s string, tab bool) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case unicode.IsPrint(r), r == '\t' && tab:
			b.WriteRune(r)
		default:
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += n
	}
	return b.String()
}

func pkglist(args []string, stdout, stderr io.Writer) error {
	fs := flags("pkglist", stderr)
	root := fs.String("root", "/", "root directory")
	if err := parse(fs, args); err != nil {
		return err
	}
	data, err := collect.ReadFile(filepath.Join(*root, "var/lib/dpkg/status"), 256<<20)
	if err != nil {
		return err
	}
	pkgs := debhash.ParseStatus(bytes.NewReader(data))
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Package < pkgs[j].Package })
	for _, p := range pkgs {
		fmt.Fprintf(stdout, "%s=%s %s\n", p.Package, p.Version, p.Arch)
	}
	return nil
}

func pkghash(args []string, stderr io.Writer) error {
	fs := flags("pkghash", stderr)
	dir := fs.String("debs", "", "directory of .deb files")
	out := fs.String("out", "", "output package-layer baseline file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *dir == "" || *out == "" {
		fs.Usage()
		return errUsage
	}
	paths, err := filepath.Glob(filepath.Join(*dir, "*.deb"))
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return fmt.Errorf("no .deb files in %s", *dir)
	}
	var debs []*debhash.Deb
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		d, err := debhash.ParseDeb(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		debs = append(debs, d)
	}
	return writeBaseline(*out, debhash.Layer(debs))
}
