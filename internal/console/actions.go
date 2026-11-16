package console

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/breakglass"
	"xdr/internal/controller"
	"xdr/internal/creds"
	"xdr/internal/fleet"
)

// Actions are what the operator can do from the console: each is an order
// to one host's agent (or a token, or a rotation) on the same paths the
// command line uses, with the same refusals.
type Actions struct {
	Dir    string
	Client func() (*clientv3.Client, error)
	Cfg    *controller.Config
	Key    ed25519.PrivateKey
	State  *State
	Now    func() time.Time
}

// Decide carries out action on the approval with that id. It is marked
// handled before the order is put, so a second click puts nothing; if the
// put fails the approval is pending again.
func (a *Actions) Decide(ctx context.Context, id, action string) error {
	ap, ok := a.State.Peek(id)
	if !ok {
		if _, err := a.State.Handle(id, action); err != nil {
			return err
		}
		return ErrUnknown
	}
	if !slices.Contains(ap.Actions, action) {
		return fmt.Errorf("%s: %q is not one of %v", id, action, ap.Actions)
	}
	if err := controller.Enrolled(a.Dir, ap.Host); err != nil {
		return err
	}
	var kind, name, sum string
	verdict := action
	switch ap.Kind {
	case "session":
		kind, name = "session", ap.Params["session"]
	case "user":
		if action == "approve" {
			if err := controller.RefuseProtected(a.Cfg, ap.Params["user"], false); err != nil {
				return err
			}
			kind, name = "user", ap.Params["user"]
		}
	case "file":
		if action == "remove" || action == "undo" {
			kind, name = "file", fleet.FileID(ap.Params["path"])
		}
	case "proc":
		if action == "kill" {
			kind, name, sum = "proc", ap.Params["pid"], ap.Params["sha256"]
		}
	}
	if _, err := a.State.Handle(id, action); err != nil {
		return err
	}
	if kind == "" {
		return nil // ignore, keep: nothing to send
	}
	c, err := a.Client()
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		err = controller.PutOrder(cctx, c, ap.Host, kind, name, controller.OrderValue(verdict, a.Now(), sum))
	}
	if err != nil {
		a.State.Unhandle(id)
		return err
	}
	return nil
}

// Rotate is the rotation of the command line; see controller.Rotate.
func (a *Actions) Rotate(ctx context.Context, host string, users, samba []string) ([]controller.Rotated, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return controller.Rotate(cctx, a.Dir, a.Cfg, controller.RotateSpec{Host: host, Users: users, Samba: samba}, a.Client)
}

// CredEntry is one stored credential.
type CredEntry struct {
	Host, Service, Account, Password string
	Rotated                          time.Time
}

// Entries are the stored credentials, by host and account.
func (a *Actions) Entries() []CredEntry {
	store, err := creds.Load(a.Dir)
	if err != nil {
		return nil
	}
	var out []CredEntry
	for host, accts := range store.Hosts {
		for acct, e := range accts {
			out = append(out, CredEntry{host, e.Service, acct, e.Password, e.Rotated})
		}
	}
	slices.SortFunc(out, func(x, y CredEntry) int {
		if x.Host != y.Host {
			return cmpStr(x.Host, y.Host)
		}
		return cmpStr(x.Account, y.Account)
	})
	return out
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Creds is the block for the scoring engine: host, service, account,
// password, one line each.
func (a *Actions) Creds() string {
	store, err := creds.Load(a.Dir)
	if err != nil {
		return ""
	}
	return store.Block("")
}

// Breakglass mints one token, valid from now for minutes (5 to 1440), for
// an enrolled host.
func (a *Actions) Breakglass(host, action string, minutes int) (string, error) {
	if !breakglass.Action(action) {
		return "", fmt.Errorf("action %q: pause, approve-session or uninstall", action)
	}
	if minutes < 5 || minutes > 1440 {
		return "", fmt.Errorf("minutes %d: between 5 and 1440", minutes)
	}
	if err := controller.Enrolled(a.Dir, host); err != nil {
		return "", err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := a.Now()
	return breakglass.Mint(breakglass.Token{V: 1, ID: hex.EncodeToString(id), Host: host, Action: action, NotBefore: now, Expires: now.Add(time.Duration(minutes) * time.Minute)}, a.Key), nil
}
