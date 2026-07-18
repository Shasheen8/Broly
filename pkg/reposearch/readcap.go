package reposearch

import (
	"fmt"
	"os"
)

func readFileCapped(absPath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d byte limit", maxBytes)
	}
	return os.ReadFile(absPath)
}
