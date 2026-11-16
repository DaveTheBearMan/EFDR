package baseline

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
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

// Schema is the only baseline schema this build reads.
const Schema = 1

// maxDecoded bounds the decompressed size of a baseline.
var maxDecoded int64 = 1 << 30

// Load reads a baseline written by Save.
func Load(r io.Reader) (*Baseline, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	lr := &io.LimitedReader{R: zr, N: maxDecoded + 1}
	var b Baseline
	if err := json.NewDecoder(lr).Decode(&b); err != nil {
		if lr.N <= 0 {
			return nil, fmt.Errorf("baseline larger than %d bytes", maxDecoded)
		}
		return nil, err
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("baseline larger than %d bytes", maxDecoded)
	}
	if b.Schema != Schema {
		return nil, fmt.Errorf("baseline schema %d, want %d", b.Schema, Schema)
	}
	if b.Files == nil {
		b.Files = map[string]FileEntry{}
	}
	return &b, nil
}
