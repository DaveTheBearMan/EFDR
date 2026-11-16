package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"syscall"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/creds"
	"xdr/internal/fleet"
	"xdr/internal/pki"
)

// UserName is what a rotated or approved account's name must look like.
var UserName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Enrolled is nil when host is an enrolled host.
func Enrolled(dir, host string) error {
	hosts, err := pki.Hosts(dir)
	if err != nil {
		return err
	}
	if !slices.Contains(hosts, host) {
		return fmt.Errorf("%s is not enrolled", host)
	}
	return nil
}

// RefuseProtected refuses a gray account, and with rotation also the
// recovery and platform accounts, as the controller config lists them.
func RefuseProtected(cfg *Config, user string, rotation bool) error {
	if slices.Contains(cfg.GrayUsers, user) {
		return fmt.Errorf("refused: %s is a protected account", user)
	}
	if rotation && (user == cfg.Recovery || slices.Contains(cfg.Auto, user)) {
		return fmt.Errorf("refused: %s is the recovery or a platform account; it is not rotated", user)
	}
	return nil
}

// RotateSpec is one rotation: new passwords for Users on Host (Samba names
// the ones Samba also knows), optionally new authorized_keys and host keys.
type RotateSpec struct {
	Host     string
	Users    []string
	Samba    []string
	Keys     []string // nil: leave authorized_keys alone
	HostKeys bool
}

// Rotated is one new password, for the operator and the scoring engine.
type Rotated struct{ Host, Service, User, Password string }

// Rotate generates new passwords, keeps them in the jump box's store, then
// sends the host's agent their hashes (never the passwords). The store is
// written first: a failure leaves a password that may not be in force,
// never a hash nobody knows. client is called only once the store is
// written; the client it returns is the caller's to close.
func Rotate(ctx context.Context, dir string, cfg *Config, spec RotateSpec, client func() (*clientv3.Client, error)) ([]Rotated, error) {
	if len(spec.Users) == 0 {
		return nil, fmt.Errorf("no users")
	}
	for _, u := range spec.Users {
		if !UserName.MatchString(u) {
			return nil, fmt.Errorf("%q is not a user name", u)
		}
		if err := RefuseProtected(cfg, u, true); err != nil {
			return nil, err
		}
	}
	for _, u := range spec.Samba {
		if !slices.Contains(spec.Users, u) {
			return nil, fmt.Errorf("--samba %s is not in --users", u)
		}
	}
	if err := Enrolled(dir, spec.Host); err != nil {
		return nil, err
	}
	// One rotation at a time on this box (two tabs) and across processes (a
	// tab and the command line): the store and the standing order change
	// together, or a stored password is not the one in force.
	rotateMu.Lock()
	defer rotateMu.Unlock()
	lock, err := os.OpenFile(filepath.Join(dir, "creds.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	store, err := creds.Load(dir)
	if err != nil {
		return nil, err
	}
	pw := map[string]string{}
	now := time.Now().UTC()
	for _, u := range spec.Users {
		pw[u] = creds.Password()
		svc := "ssh"
		if slices.Contains(spec.Samba, u) {
			svc = "samba"
		}
		store.Put(spec.Host, u, creds.Entry{Password: pw[u], Service: svc, Rotated: now})
	}
	if err := store.Save(); err != nil {
		return nil, err
	}
	set := creds.NewSet(pw, spec.Samba, spec.Keys, spec.HostKeys)
	c, err := client()
	if err != nil {
		return nil, fmt.Errorf("passwords stored, not sent: %w", err)
	}
	// The order is one key, replaced each time: an agent that was away for
	// two rotations would apply only the last. So a new set carries the
	// accounts of the standing one too (this rotation's win).
	if cur, err := standingSet(ctx, c, spec.Host); err == nil {
		for u, e := range cur.Users {
			if _, ok := set.Users[u]; !ok && len(set.Users) < maxSetUsers {
				set.Users[u] = e
			}
		}
	}
	if err := PutOrder(ctx, c, spec.Host, "creds", "", set); err != nil {
		return nil, fmt.Errorf("passwords stored, not sent (run rotate again): %w", err)
	}
	var out []Rotated
	for _, u := range spec.Users {
		out = append(out, Rotated{spec.Host, store.Hosts[spec.Host][u].Service, u, pw[u]})
	}
	return out, nil
}

// OrderValue is an order's JSON: the verdict, when it was put (so an agent
// can tell one left over from before its boot: session ids restart at every
// boot) and, for a process order, the hash of the binary it is for.
func OrderValue(verdict string, at time.Time, sha256 string) map[string]any {
	v := map[string]any{"verdict": verdict, "at": at.Unix()}
	if sha256 != "" {
		v["sha256"] = sha256
	}
	return v
}

// maxSetUsers bounds the accounts one credential order carries.
const maxSetUsers = 256

var rotateMu sync.Mutex

// standingSet is the credential order standing for host, or an empty set.
func standingSet(ctx context.Context, c *clientv3.Client, host string) (creds.Set, error) {
	var set creds.Set
	r, err := c.Get(ctx, fleet.To(host)+"creds")
	if err != nil || len(r.Kvs) == 0 {
		return set, err
	}
	err = json.Unmarshal(r.Kvs[0].Value, &set)
	return set, err
}
