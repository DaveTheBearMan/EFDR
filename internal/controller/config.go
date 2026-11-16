package controller

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"

	"xdr/internal/baseline"
	"xdr/internal/config"
	"xdr/internal/rules"
)

// Config is the controller's deployment config, controller.json in its
// directory.
type Config struct {
	Listen    string       `json:"listen"`     // host:port agents reach etcd at
	Protect   []config.Net `json:"protect"`    // addresses no rule may name
	GuardExes []string     `json:"guard_exes"` // scored-service binaries on any host
	Baselines []string     `json:"baselines"`  // layers over the embedded baseline
	GrayUsers []string     `json:"gray_users"` // accounts no order or rotation may touch
	Recovery  string       `json:"recovery"`   // the recovery account: its key is held off-box, never rotated
	Auto      []string     `json:"auto"`       // platform accounts: never rotated
	Console   *Console     `json:"console"`    // nil: no web console
}

// Console is where the operator's web console listens.
type Console struct {
	Listen string `json:"listen"` // host:port, HTTPS
}

// LoadConfig reads and checks a controller config.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return nil, fmt.Errorf("%s: listen %q: %w", path, c.Listen, err)
	}
	if c.Console != nil {
		if _, _, err := net.SplitHostPort(c.Console.Listen); err != nil {
			return nil, fmt.Errorf("%s: console.listen %q: %w", path, c.Console.Listen, err)
		}
	}
	return &c, nil
}

// Guard is what the controller checks proposals against.
func (c *Config) Guard() (rules.Guard, error) {
	base, err := baseline.LoadLayers(c.Baselines)
	if err != nil {
		return rules.Guard{}, err
	}
	var protect []netip.Prefix
	for _, n := range c.Protect {
		protect = append(protect, n.Prefix)
	}
	return rules.Guard{Baseline: rules.BaselineHashes(base), GuardExes: c.GuardExes, Protect: protect}, nil
}
