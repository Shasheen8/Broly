// Package cache provides a file-hash cache for incremental scanning.
// Only files whose content has changed since the last run are rescanned.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

const DefaultPath = ".broly-cache.json"

type Cache struct {
	Hashes map[string]string `json:"hashes"`
	path   string
}

// Load reads the cache from disk. Returns an empty cache if the file does not exist.
func Load(path string) (*Cache, error) {
	c := &Cache{Hashes: make(map[string]string), path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		// Corrupt cache — start fresh rather than failing.
		c.Hashes = make(map[string]string)
	}
	c.path = path
	return c, nil
}

// Save writes the cache to disk.
func (c *Cache) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

// Changed reports whether the file has changed since it was last recorded.
// Returns true for files that cannot be read or have not been seen before.
func (c *Cache) Changed(path string) bool {
	hash, err := hashFile(path)
	if err != nil {
		return true
	}
	return c.Hashes[path] != hash
}

// Update records the current hash for a file.
func (c *Cache) Update(path string) {
	if hash, err := hashFile(path); err == nil {
		c.Hashes[path] = hash
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
