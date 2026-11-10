package baseline

import (
	"compress/gzip"
	"encoding/json"
	"io"
)

// Save writes b as gzip-compressed JSON.
func Save(w io.Writer, b *Baseline) error {
	zw := gzip.NewWriter(w)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return err
	}
	return zw.Close()
}

// Load reads a baseline written by Save.
func Load(r io.Reader) (*Baseline, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var b Baseline
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		return nil, err
	}
	if b.Files == nil {
		b.Files = map[string]FileEntry{}
	}
	return &b, nil
}
