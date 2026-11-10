// Package model holds types shared across xdr components.
package model

import (
	"encoding/json"
	"fmt"
)

// Kind is how a finding differs from the baseline.
type Kind string

const (
	KindAdded   Kind = "added"
	KindAltered Kind = "altered"
	KindRemoved Kind = "removed"
	KindError   Kind = "error" // could not be read, so could not be compared
)

// Severity orders findings from informational to critical.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var sevNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < SevInfo || s > SevCritical {
		return "unknown"
	}
	return sevNames[s]
}

// MarshalJSON encodes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON decodes a severity from its name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	for i, n := range sevNames {
		if n == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", name)
}

// Finding is one difference between a baseline and a live snapshot.
type Finding struct {
	Kind     Kind     `json:"kind"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Subject  string   `json:"subject"`
	Detail   string   `json:"detail"`
	Before   string   `json:"before"`
	After    string   `json:"after"`
	Diff     string   `json:"diff"`
}
