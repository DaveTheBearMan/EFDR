package baseline

import (
	"bytes"
	_ "embed"
)

// embedded is the clean base-image baseline compiled into the binary.
//
//go:embed data/base.json.gz
var embedded []byte

// Embedded returns the baseline compiled into the binary.
func Embedded() (*Baseline, error) {
	return Load(bytes.NewReader(embedded))
}
