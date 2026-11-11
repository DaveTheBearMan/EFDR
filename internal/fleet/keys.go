// Package fleet is the agent's side of the fleet: the etcd key schema and
// the client that watches signed rules and reports to the controller.
package fleet

import "strings"

// The etcd keys. A host writes only under its own Proposed, Incidents and
// Heartbeat keys; only the controller writes RulesKey.
const (
	Prefix       = "/xdr/"
	RulesKey     = "/xdr/rules"
	ProposedAll  = "/xdr/proposed/"
	IncidentsAll = "/xdr/incidents/"
	HeartbeatAll = "/xdr/heartbeat/"
)

// Proposed is the prefix of host's proposed rules, one key per rule id.
func Proposed(host string) string { return ProposedAll + host + "/" }

// Incidents is the prefix of host's incident lines.
func Incidents(host string) string { return IncidentsAll + host + "/" }

// Heartbeat is host's heartbeat key.
func Heartbeat(host string) string { return HeartbeatAll + host }

// HostOf is the host a key under prefix belongs to, and the rest of the
// key after the host.
func HostOf(key, prefix string) (host, rest string, ok bool) {
	tail, ok := strings.CutPrefix(key, prefix)
	if !ok || tail == "" {
		return "", "", false
	}
	host, rest, _ = strings.Cut(tail, "/")
	return host, rest, host != ""
}
