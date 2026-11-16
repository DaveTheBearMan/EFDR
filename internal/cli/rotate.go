package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"xdr/internal/controller"
	"xdr/internal/creds"
)

// rotateCmd is `xdr controller rotate --host H --users a,b [--samba a]
// [--keys FILE] [--hostkeys]`: new passwords, kept here, their hashes sent
// to H's agent. The store is written before etcd, so a failure leaves a
// password that may not be in force, never a hash nobody knows.
func rotateCmd(rest []string, stdout, stderr io.Writer) error {
	fs := flags("controller rotate", stderr)
	dir := fs.String("dir", "", "controller directory")
	host := fs.String("host", "", "enrolled host")
	users := fs.String("users", "", "accounts, comma-separated")
	samba := fs.String("samba", "", "of those, accounts Samba also knows (they get an NT hash)")
	keysFile := fs.String("keys", "", "authorized_keys to give each account")
	hostKeys := fs.Bool("hostkeys", false, "regenerate the host's SSH host keys")
	endpoint := fs.String("endpoint", "", "etcd address (default: listen in DIR/controller.json)")
	if err := parse(fs, rest); err != nil {
		return err
	}
	if *dir == "" || *host == "" || *users == "" {
		fmt.Fprint(stderr, "xdr controller rotate: --dir, --host and --users are required\n")
		return errUsage
	}
	names := strings.Split(*users, ",")
	var sambaNames []string
	if *samba != "" {
		sambaNames = strings.Split(*samba, ",")
	}
	for _, u := range names {
		if !userArg.MatchString(u) {
			return fmt.Errorf("%q is not a user name", u)
		}
		if err := refuseProtected(*dir, u, true); err != nil {
			return err
		}
	}
	for _, u := range sambaNames {
		if !slices.Contains(names, u) {
			return fmt.Errorf("--samba %s is not in --users", u)
		}
	}
	var keys []string
	if *keysFile != "" {
		b, err := os.ReadFile(*keysFile)
		if err != nil {
			return err
		}
		keys = []string{}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
				keys = append(keys, l)
			}
		}
	}
	if err := enrolled(*dir, *host); err != nil {
		return err
	}
	store, err := creds.Load(*dir)
	if err != nil {
		return err
	}
	pw := map[string]string{}
	now := time.Now().UTC()
	for _, u := range names {
		pw[u] = creds.Password()
		svc := "ssh"
		if slices.Contains(sambaNames, u) {
			svc = "samba"
		}
		store.Put(*host, u, creds.Entry{Password: pw[u], Service: svc, Rotated: now})
	}
	if err := store.Save(); err != nil {
		return err
	}
	set := creds.NewSet(pw, sambaNames, keys, *hostKeys)
	c, err := rootClient(*dir, *endpoint)
	if err != nil {
		return fmt.Errorf("passwords stored, not sent: %w", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := controller.PutOrder(ctx, c, *host, "creds", "", set); err != nil {
		return fmt.Errorf("passwords stored, not sent (run rotate again): %w", err)
	}
	for _, u := range names {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", *host, store.Hosts[*host][u].Service, u, pw[u])
	}
	return nil
}

// credsCmd is `xdr controller creds [--host H]`: the stored passwords.
func credsCmd(rest []string, stdout, stderr io.Writer) error {
	fs := flags("controller creds", stderr)
	dir := fs.String("dir", "", "controller directory")
	host := fs.String("host", "", "only this host")
	if err := parse(fs, rest); err != nil {
		return err
	}
	if *dir == "" {
		fmt.Fprint(stderr, "xdr controller creds: --dir is required\n")
		return errUsage
	}
	store, err := creds.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Fprint(stdout, store.Block(*host))
	return nil
}
