package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

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
	spec := controller.RotateSpec{Host: *host, Users: strings.Split(*users, ","), HostKeys: *hostKeys}
	if *samba != "" {
		spec.Samba = strings.Split(*samba, ",")
	}
	if *keysFile != "" {
		b, err := os.ReadFile(*keysFile)
		if err != nil {
			return err
		}
		spec.Keys = []string{}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
				spec.Keys = append(spec.Keys, l)
			}
		}
	}
	cfg, err := controller.LoadConfig(filepath.Join(*dir, "controller.json"))
	if err != nil {
		return err
	}
	var c *clientv3.Client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := controller.Rotate(ctx, *dir, cfg, spec, func() (*clientv3.Client, error) {
		var err error
		c, err = rootClient(*dir, *endpoint)
		return c, err
	})
	if c != nil {
		defer c.Close()
	}
	if err != nil {
		return err
	}
	for _, r := range out {
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", r.Host, r.Service, r.User, r.Password)
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
