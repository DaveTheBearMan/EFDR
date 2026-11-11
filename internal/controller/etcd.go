// Package controller is the jump box's side of the fleet: the etcd server,
// rule promotion and signing, incident intake and heartbeat watch.
package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"time"

	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"xdr/internal/fleet"
	"xdr/internal/pki"
)

const readyTimeout = 10 * time.Second

// localPort is a loopback address for etcd's peer listener, which no
// other member ever dials.
func localPort() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

// StartEtcd starts the single etcd member on listen (host:port), TLS only
// and client certs required, with its data under dir/etcd. It returns the
// server and a client authenticated as root.
func StartEtcd(dir, listen string) (*embed.Etcd, *clientv3.Client, error) {
	if _, _, err := net.SplitHostPort(listen); err != nil {
		return nil, nil, fmt.Errorf("listen %q: %w", listen, err)
	}
	peer, err := localPort()
	if err != nil {
		return nil, nil, err
	}
	cfg := embed.NewConfig()
	cfg.Name = "xdr"
	cfg.Dir = filepath.Join(dir, "etcd")
	client := url.URL{Scheme: "https", Host: listen}
	peers := url.URL{Scheme: "http", Host: peer}
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{client}, []url.URL{client}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{peers}, []url.URL{peers}
	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)
	cfg.ClientTLSInfo = transport.TLSInfo{
		CertFile:       filepath.Join(dir, "server.pem"),
		KeyFile:        filepath.Join(dir, "server-key.pem"),
		TrustedCAFile:  filepath.Join(dir, "ca.pem"),
		ClientCertAuth: true,
	}
	// Without compaction every put stays in history until the backend
	// quota is full, and then etcd refuses all writes, fleet-wide.
	cfg.AutoCompactionMode, cfg.AutoCompactionRetention = "periodic", "5m"
	cfg.LogLevel = "error"
	cfg.LogOutputs = []string{filepath.Join(dir, "etcd.log")}
	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return nil, nil, err
	}
	select {
	case <-e.Server.ReadyNotify():
	case err := <-e.Err():
		e.Close()
		return nil, nil, err
	case <-time.After(readyTimeout):
		e.Close()
		return nil, nil, errors.New("etcd: not ready after 10s")
	}
	tc, err := pki.ClientTLS(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "root.pem"), filepath.Join(dir, "root-key.pem"))
	if err != nil {
		e.Close()
		return nil, nil, err
	}
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{listen}, TLS: tc, DialTimeout: 5 * time.Second})
	if err != nil {
		e.Close()
		return nil, nil, err
	}
	return e, c, nil
}

func exists(err error) bool {
	return errors.Is(err, rpctypes.ErrUserAlreadyExist) || errors.Is(err, rpctypes.ErrRoleAlreadyExist)
}

// user adds name, with no password (the cert's CN logs it in), and grants
// it role.
func user(ctx context.Context, c *clientv3.Client, name, role string) error {
	if _, err := c.UserAddWithOptions(ctx, name, "", &clientv3.UserAddOptions{NoPassword: true}); err != nil && !exists(err) {
		return fmt.Errorf("user %s: %w", name, err)
	}
	if _, err := c.UserGrantRole(ctx, name, role); err != nil {
		return fmt.Errorf("user %s: %w", name, err)
	}
	return nil
}

// revokeWrites takes away host's write access; it may still read the
// rule set.
func revokeWrites(ctx context.Context, c *clientv3.Client, h string) error {
	for _, p := range []struct{ key, end string }{
		{fleet.Proposed(h), clientv3.GetPrefixRangeEnd(fleet.Proposed(h))},
		{fleet.Incidents(h), clientv3.GetPrefixRangeEnd(fleet.Incidents(h))},
		{fleet.Heartbeat(h), ""},
	} {
		// No role yet: the next Bootstrap sees DisabledAll and revokes then.
		_, err := c.RoleRevokePermission(ctx, "host-"+h, p.key, p.end)
		if err != nil && !errors.Is(err, rpctypes.ErrPermissionNotGranted) && !errors.Is(err, rpctypes.ErrRoleNotFound) {
			return fmt.Errorf("role host-%s: %w", h, err)
		}
	}
	return nil
}

func role(ctx context.Context, c *clientv3.Client, name string) error {
	if _, err := c.RoleAdd(ctx, name); err != nil && !exists(err) {
		return fmt.Errorf("role %s: %w", name, err)
	}
	return nil
}

// Bootstrap sets up users and roles and turns auth on: root may do
// anything; each host may write its own proposals, incidents and
// heartbeat, and read the rule set. Running it again adds hosts enrolled
// since.
func Bootstrap(ctx context.Context, c *clientv3.Client, hosts []string) error {
	if err := role(ctx, c, "root"); err != nil {
		return err
	}
	if err := user(ctx, c, "root", "root"); err != nil {
		return err
	}
	rw := clientv3.PermissionType(clientv3.PermReadWrite)
	for _, h := range hosts {
		r := "host-" + h
		if err := role(ctx, c, r); err != nil {
			return err
		}
		for _, p := range []struct {
			key, end string
			perm     clientv3.PermissionType
		}{
			{fleet.Proposed(h), clientv3.GetPrefixRangeEnd(fleet.Proposed(h)), rw},
			{fleet.Incidents(h), clientv3.GetPrefixRangeEnd(fleet.Incidents(h)), rw},
			{fleet.Heartbeat(h), "", rw},
			{fleet.RulesKey, "", clientv3.PermissionType(clientv3.PermRead)},
		} {
			if _, err := c.RoleGrantPermission(ctx, r, p.key, p.end, p.perm); err != nil {
				return fmt.Errorf("role %s: %w", r, err)
			}
		}
		if err := user(ctx, c, h, r); err != nil {
			return err
		}
		resp, err := c.Get(ctx, fleet.DisabledAll+h)
		if err != nil {
			return err
		}
		if len(resp.Kvs) > 0 {
			if err := revokeWrites(ctx, c, h); err != nil {
				return err
			}
		}
	}
	if _, err := c.AuthEnable(ctx); err != nil {
		return fmt.Errorf("auth enable: %w", err)
	}
	return nil
}
