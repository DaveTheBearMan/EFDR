package fw

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// BlocksFile is where the agent keeps the fleet's blocks it has in force:
// it does not announce them again after a restart, and `xdr fw` builds its
// table with them.
const BlocksFile = "/var/lib/xdr/blocks.json"

// SaveBlocks writes blocks to path atomically, readable by root only.
func SaveBlocks(path string, blocks []Block) error {
	if blocks == nil {
		blocks = []Block{}
	}
	b, err := json.Marshal(blocks)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadBlocks reads what SaveBlocks wrote; a missing file is no blocks.
func LoadBlocks(path string) ([]Block, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Block
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
