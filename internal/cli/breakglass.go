package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/collect"
	"xdr/internal/config"
	"xdr/internal/pki"
	"xdr/internal/rules"
	"xdr/internal/sshgate"
)

// spoolDir is where `xdr breakglass` leaves tokens.
var spoolDir = breakglass.Spool

func init() {
	// The gate's way in with the agent down: a pause token for this host,
	// checked with the fleet bundle's rule key and host certificate.
	gatePaused = func() bool {
		pub, err := rules.LoadPublic(filepath.Join(config.DefaultFleetDir, "rules.pub"))
		if err != nil {
			return false
		}
		host, err := pki.HostName(filepath.Join(config.DefaultFleetDir, "host.pem"))
		if err != nil {
			return false
		}
		return breakglass.Paused(spoolDir, pub, host, time.Now())
	}
}

// breakglassCmd is `xdr breakglass TOKEN|- [--session ID]`: the token goes
// to the agent, for the caller's own session unless one is named, and to
// the spool, where the gate and a restarted agent find it.
func breakglassCmd(args []string, stdout, stderr io.Writer) error {
	fs := flags("breakglass", stderr)
	session := fs.String("session", "", "session to approve (default: this one)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, "xdr breakglass: one token (or - for stdin) is required\n")
		return errUsage
	}
	tok := fs.Arg(0)
	if tok == "-" {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return err
		}
		tok = string(b)
	}
	tok = strings.TrimSpace(tok)
	sess := *session
	if sess == "" {
		sess = os.Getenv("XDG_SESSION_ID")
	}
	if sess == "" {
		cg, _ := collect.ReadFile("/proc/self/cgroup", 4096)
		sess = sshgate.CgroupSession(cg)
	}
	sum := sha256.Sum256([]byte(tok))
	name := filepath.Join(spoolDir, hex.EncodeToString(sum[:8])+".tok")
	if err := os.WriteFile(name, []byte(tok+"\n"+sess+"\n"), 0o600); err != nil {
		fmt.Fprintf(stderr, "xdr breakglass: not spooled: %v\n", err)
	}
	r, err := sshgate.Send(gateSocket, sshgate.Msg{Token: tok, Session: sess})
	if err != nil {
		fmt.Fprintln(stdout, "agent down: token spooled")
		return nil
	}
	if !r.OK {
		return fmt.Errorf("refused: %s", r.Why)
	}
	if sess != "" {
		fmt.Fprintf(stdout, "%s: session %s\n", r.Why, sess)
	} else {
		fmt.Fprintln(stdout, r.Why)
	}
	return nil
}

// mintCmd is `xdr controller mint-breakglass`: a file per host per window,
// each window `every` long, starting at `from`.
func mintCmd(rest []string, stdout, stderr io.Writer) error {
	fs := flags("controller mint-breakglass", stderr)
	dir := fs.String("dir", "", "controller directory")
	hosts := fs.String("hosts", "", "enrolled hosts, comma-separated")
	action := fs.String("action", "", "pause, approve-session or uninstall")
	from := fs.String("from", "", "start of the first window (RFC 3339)")
	every := fs.Duration("every", 2*time.Hour, "window length")
	count := fs.Int("count", 1, "windows per host")
	out := fs.String("out", "", "directory to write the tokens to (must not exist)")
	if err := parse(fs, rest); err != nil {
		return err
	}
	if *dir == "" || *hosts == "" || *from == "" || *out == "" {
		fmt.Fprint(stderr, "xdr controller mint-breakglass: --dir, --hosts, --action, --from and --out are required\n")
		return errUsage
	}
	if !breakglass.Action(*action) {
		return fmt.Errorf("--action %q: pause, approve-session or uninstall", *action)
	}
	start, err := time.Parse(time.RFC3339, *from)
	if err != nil {
		return fmt.Errorf("--from: %w", err)
	}
	if *every <= 0 || *every > 24*time.Hour || *count < 1 || *count > 1000 {
		return fmt.Errorf("--every must be in (0, 24h] and --count in [1, 1000]")
	}
	enrolled, err := pki.Hosts(*dir)
	if err != nil {
		return err
	}
	names := strings.Split(*hosts, ",")
	for _, h := range names {
		if !slices.Contains(enrolled, h) {
			return fmt.Errorf("%s is not enrolled", h)
		}
	}
	key, err := rules.LoadPrivate(filepath.Join(*dir, "rules.key"))
	if err != nil {
		return err
	}
	if err := os.Mkdir(*out, 0o700); err != nil {
		return err
	}
	for _, h := range names {
		for i := range *count {
			nb := start.Add(time.Duration(i) * *every).UTC()
			id := make([]byte, 8)
			rand.Read(id)
			t := breakglass.Token{V: 1, ID: hex.EncodeToString(id), Host: h, Action: *action, NotBefore: nb, Expires: nb.Add(*every)}
			p := filepath.Join(*out, fmt.Sprintf("%s-%s-%s.tok", h, *action, nb.Format("20060102T1504Z")))
			if err := os.WriteFile(p, []byte(breakglass.Mint(t, key)+"\n"), 0o600); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(stdout, "minted %d tokens in %s\n", len(names)**count, *out)
	return nil
}
