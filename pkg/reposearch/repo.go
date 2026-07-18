package reposearch

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultMaxReadLines   = 500
	DefaultMaxSearchHits  = 100
	DefaultMaxFindResults = 100
	DefaultMaxFileBytes   = 512 * 1024
)

type Repo struct {
	root string
}

func New(root string) (*Repo, error) {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("repo root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("repo root is not a directory")
	}
	return &Repo{root: root}, nil
}

func (r *Repo) Root() string {
	if r == nil {
		return ""
	}
	return r.root
}
