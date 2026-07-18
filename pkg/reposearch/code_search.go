package reposearch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const gitGrepTimeout = 10 * time.Second

func (r *Repo) CodeSearch(ctx context.Context, query string, filePatterns []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("repo is nil")
	}
	query = strings.TrimSpace(query)
	if query == "" {
		return "Error: search query is required", nil
	}

	if repoHasGit(r.root) {
		return r.gitGrep(ctx, query, filePatterns)
	}
	return r.walkSearch(ctx, query, filePatterns)
}

func (r *Repo) gitGrep(ctx context.Context, query string, patterns []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, gitGrepTimeout)
	defer cancel()

	args := []string{
		"--no-pager", "grep",
		"-F", "-n", "--no-color",
		"--max-count", strconv.Itoa(DefaultMaxSearchHits),
		"-e", query,
	}
	pathspec := patterns
	if len(pathspec) == 0 {
		pathspec = []string{"."}
	}
	args = append(args, "--")
	args = append(args, pathspec...)

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.root

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}

	outStr := stdout.String()
	if outStr == "" {
		if err != nil {
			if strings.TrimSpace(stderr.String()) == "" {
				return "No matches found", nil
			}
			return fmt.Sprintf("Error: %s", strings.TrimSpace(stderr.String())), nil
		}
		return "No matches found", nil
	}

	return formatGrepOutput(outStr), nil
}

func formatGrepOutput(outStr string) string {
	lines := strings.Split(strings.TrimRight(outStr, "\n"), "\n")
	truncated := len(lines) >= DefaultMaxSearchHits

	type match struct {
		lineNum int
		content string
	}
	fileMatches := make(map[string][]match)
	var fileOrder []string
	seen := make(map[string]bool)

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		fname := parts[0]
		ln, parseErr := strconv.Atoi(parts[1])
		if parseErr != nil {
			continue
		}
		if !seen[fname] {
			seen[fname] = true
			fileOrder = append(fileOrder, fname)
		}
		fileMatches[fname] = append(fileMatches[fname], match{
			lineNum: ln,
			content: redactLine(parts[2]),
		})
	}

	var sb strings.Builder
	if truncated {
		fmt.Fprintf(&sb, "Note: Results truncated to first %d matches.\n", DefaultMaxSearchHits)
	}
	for _, path := range fileOrder {
		matches := fileMatches[path]
		fmt.Fprintf(&sb, "File: %s\nMatch lines: %d\n", path, len(matches))
		for _, m := range matches {
			fmt.Fprintf(&sb, "%d|%s\n", m.lineNum, m.content)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (r *Repo) walkSearch(ctx context.Context, query string, patterns []string) (string, error) {
	files, err := r.listFiles(ctx)
	if err != nil {
		return "", err
	}
	if len(patterns) > 0 {
		files = filterByPatterns(files, patterns)
	}

	type match struct {
		lineNum int
		content string
	}
	fileMatches := make(map[string][]match)
	var fileOrder []string
	hits := 0
	lowerQuery := strings.ToLower(query)

	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		abs, err := resolveRepoPath(r.root, rel)
		if err != nil {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil || info.Size() > DefaultMaxFileBytes {
			continue
		}
		data, err := readFileCapped(abs, DefaultMaxFileBytes)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(strings.ToLower(line), lowerQuery) {
				continue
			}
			if _, ok := fileMatches[rel]; !ok {
				fileOrder = append(fileOrder, rel)
			}
			fileMatches[rel] = append(fileMatches[rel], match{
				lineNum: i + 1,
				content: redactLine(line),
			})
			hits++
			if hits >= DefaultMaxSearchHits {
				break
			}
		}
		if hits >= DefaultMaxSearchHits {
			break
		}
	}

	if len(fileOrder) == 0 {
		return "No matches found", nil
	}

	var sb strings.Builder
	if hits >= DefaultMaxSearchHits {
		fmt.Fprintf(&sb, "Note: Results truncated to first %d matches.\n", DefaultMaxSearchHits)
	}
	for _, path := range fileOrder {
		matches := fileMatches[path]
		fmt.Fprintf(&sb, "File: %s\nMatch lines: %d\n", path, len(matches))
		for _, m := range matches {
			fmt.Fprintf(&sb, "%d|%s\n", m.lineNum, redactLine(m.content))
		}
		sb.WriteString("\n")
	}
	return sb.String(), nil
}

func filterByPatterns(files, patterns []string) []string {
	if len(patterns) == 0 {
		return files
	}
	out := make([]string, 0, len(files))
	for _, f := range files {
		for _, p := range patterns {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.Contains(f, strings.TrimPrefix(p, "**/")) || strings.HasSuffix(f, p) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}
