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
