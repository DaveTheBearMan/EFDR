package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/fleet"
	"xdr/internal/pki"
)

const maxOrder = 64 << 10

// PutOrder puts v, as JSON, at host's order kind/name (kind alone when
// name is ""). Only root may write there; the host reads it.
func PutOrder(ctx context.Context, c *clientv3.Client, host, kind, name string, v any) error {
	key := fleet.To(host) + kind
	if name != "" {
		key += "/" + name
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxOrder {
		return fmt.Errorf("order %s: %d bytes, over %d", key, len(b), maxOrder)
	}
	_, err = c.Put(ctx, key, string(b))
	return err
}

// Mode is the value of a host's `mode` order: whether its agent kills
// what it decides to kill, when the operator chose it (the agent keeps the
// latest) and who did. It is state, not an event: the agent applies the
// latest and keeps it across a restart. It changes nothing of what is
// protected (scored services, gray accounts, a pause).
type Mode struct {
	Kill bool      `json:"kill"`
	At   time.Time `json:"at"`
	By   string    `json:"by,omitempty"`
}

// PutMode puts m as the mode order of each of hosts, or of every enrolled
// host when hosts is nil, and says which hosts it was put for. Every host
// named must be enrolled; nothing is put when one is not.
func PutMode(ctx context.Context, c *clientv3.Client, dir string, hosts []string, m Mode) ([]string, error) {
	if m.At.IsZero() {
		return nil, errors.New("mode order: no time")
	}
	enrolled, err := pki.Hosts(dir)
	if err != nil {
		return nil, err
	}
	if hosts == nil {
		hosts = enrolled
	}
	hosts = slices.Clone(hosts)
	slices.Sort(hosts)
	for _, h := range hosts {
		if !slices.Contains(enrolled, h) {
			return nil, fmt.Errorf("%s is not enrolled", h)
		}
	}
	var done []string
	for _, h := range hosts {
		if err := PutOrder(ctx, c, h, "mode", "", m); err != nil {
			return done, fmt.Errorf("%s: %w", h, err)
		}
		done = append(done, h)
	}
	return done, nil
}
