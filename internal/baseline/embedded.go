package baseline

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
)

// embedded is the clean base-image baseline compiled into the binary.
//
//go:embed data/base.json.gz
var embedded []byte

// Embedded returns the baseline compiled into the binary.
func Embedded() (*Baseline, error) {
	return Load(bytes.NewReader(embedded))
}

// LoadLayers is the embedded baseline with the layer files at paths
// composed over it, in order.
func LoadLayers(paths []string) (*Baseline, error) {
	base, err := Embedded()
	if err != nil {
		return nil, err
	}
	layers := []*Baseline{base}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		b, err := Load(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		layers = append(layers, b)
	}
	return Compose(layers...), nil
}
