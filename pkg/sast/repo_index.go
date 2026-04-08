package sast

import (
	"os"
	"path/filepath"
	"strings"
)

type repoIndex struct {
	root         string
	goModulePath string
}

func newRepoIndex(root string) *repoIndex {
	return &repoIndex{
		root:         root,
		goModulePath: readGoModulePath(root),
	}
}

func (r *repoIndex) resolveLocalGoImport(importPath string) (string, bool) {
	if r == nil || r.goModulePath == "" {
		return "", false
	}
	if importPath == r.goModulePath {
		return r.root, true
	}
	prefix := r.goModulePath + "/"
	if !strings.HasPrefix(importPath, prefix) {
		return "", false
	}

	rel := strings.TrimPrefix(importPath, prefix)
	dir := filepath.Join(r.root, filepath.FromSlash(rel))
	if !pathWithinRoot(r.root, dir) {
		return "", false
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}

	return dir, true
}

func readGoModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}
