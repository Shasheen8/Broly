package reposearch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const gitListTimeout = 10 * time.Second

func (r *Repo) FindFiles(ctx context.Context, query string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("repo is nil")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return "No files matched", nil
	}

	files, err := r.listFiles(ctx)
	if err != nil {
		return "", err
	}

	var matched []string
	lowerQuery := strings.ToLower(query)
	for _, f := range files {
		base := f
		if idx := strings.LastIndex(f, "/"); idx != -1 {
			base = f[idx+1:]
		}
		if strings.Contains(strings.ToLower(base), lowerQuery) {
			matched = append(matched, f)
		}
		if len(matched) >= DefaultMaxFindResults {
			break
		}
	}

	if len(matched) == 0 {
		return "No files matched", nil
	}
	return strings.Join(matched, "\n"), nil
}

func (r *Repo) listFiles(ctx context.Context) ([]string, error) {
	if repoHasGit(r.root) {
		return r.gitListFiles(ctx)
	}
	return r.walkListFiles(ctx)
}

func (r *Repo) gitListFiles(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitListTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard")
	cmd.Dir = r.root
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	var files []string
	for _, line := range bytes.Split(bytes.TrimRight(output, "\n"), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		s := string(line)
		if shouldSkipListedFile(s) {
			continue
		}
		files = append(files, s)
	}
	return files, nil
}

func shouldSkipListedFile(path string) bool {
	base := path
	if idx := strings.LastIndex(path, "/"); idx != -1 {
		base = path[idx+1:]
	}
	if strings.Contains(base, ".") {
		return false
	}
	switch base {
	case "Makefile", "Dockerfile", "LICENSE", "Vagrantfile", "Containerfile":
		return false
	default:
		return true
	}
}

func (r *Repo) walkListFiles(ctx context.Context) ([]string, error) {
	var files []string
	err := filepath.WalkDir(r.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(r.root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if shouldSkipListedFile(rel) {
			return nil
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}
