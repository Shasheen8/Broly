package reposearch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func ResolveAbsPath(root, path string) (string, error) {
	if filepath.IsAbs(path) {
		return resolveAbsUnderRoot(root, path)
	}
	return resolveRepoPath(root, path)
}

func RepoRelativePath(repoRoot, filePath string) string {
	if repoRoot == "" || filePath == "" {
		return filePath
	}
	rel, err := filepath.Rel(repoRoot, filePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(strings.TrimPrefix(filepath.Base(filePath), "/"))
	}
	return filepath.ToSlash(rel)
}

func resolveAbsUnderRoot(root, absPath string) (string, error) {
	rootAbs, err := absRoot(root)
	if err != nil {
		return "", err
	}
	joinedAbs, err := filepath.Abs(absPath)
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(joinedAbs); err == nil {
		joinedAbs = eval
	}
	if joinedAbs != rootAbs && !strings.HasPrefix(joinedAbs, rootAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repo root")
	}
	return joinedAbs, nil
}

func absRoot(root string) (string, error) {
	root = filepath.Clean(root)
	if root == "" {
		return "", fmt.Errorf("repo root is empty")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = eval
	}
	return rootAbs, nil
}

func resolveRepoPath(root, relPath string) (string, error) {
	root = filepath.Clean(root)
	if root == "" {
		return "", fmt.Errorf("repo root is empty")
	}
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	relPath = strings.TrimPrefix(relPath, "/")
	if relPath == "" || relPath == "." {
		return "", fmt.Errorf("file path is required")
	}
	if strings.Contains(relPath, "..") {
		return "", fmt.Errorf("path traversal is not allowed")
	}

	rootAbs, err := absRoot(root)
	if err != nil {
		return "", err
	}
	joined := filepath.Join(rootAbs, filepath.FromSlash(relPath))
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if eval, err := filepath.EvalSymlinks(joinedAbs); err == nil {
		joinedAbs = eval
	}
	if joinedAbs != rootAbs && !strings.HasPrefix(joinedAbs, rootAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repo root")
	}
	return joinedAbs, nil
}

func repoHasGit(root string) bool {
	info, err := os.Stat(filepath.Join(root, ".git"))
	return err == nil && info.IsDir()
}
