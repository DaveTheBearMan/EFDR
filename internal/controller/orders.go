package controller

import (
	"context"
	"encoding/json"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"

	"xdr/internal/fleet"
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
