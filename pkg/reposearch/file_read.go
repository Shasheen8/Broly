package reposearch

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

func (r *Repo) FileRead(ctx context.Context, relPath string, startLine, endLine int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("repo is nil")
	}

	absPath, err := resolveRepoPath(r.root, relPath)
	if err != nil {
		return "", err
	}

	data, err := readFileCapped(absPath, DefaultMaxFileBytes)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	total := len(lines)
	if total == 0 {
		return fmt.Sprintf("File: %s (Total lines: 0)\nIS_TRUNCATED: false\nLINE_RANGE: 0-0\n", filepathToSlash(relPath)), nil
	}

	if startLine <= 0 {
		startLine = 1
	}
	if endLine <= 0 || endLine > total {
		endLine = total
	}
	if startLine > endLine {
		return "", fmt.Errorf("invalid line range: %d-%d", startLine, endLine)
	}
	if startLine > total {
		return "", fmt.Errorf("file has only %d lines, requested start %d", total, startLine)
	}

	requested := endLine - startLine + 1
	truncated := requested > DefaultMaxReadLines
	if truncated {
		endLine = startLine + DefaultMaxReadLines - 1
	}

	slice := lines[startLine-1 : endLine]
	slice = redactLines(slice)

	var sb strings.Builder
	fmt.Fprintf(&sb, "File: %s (Total lines: %d)\n", filepathToSlash(relPath), total)
	fmt.Fprintf(&sb, "IS_TRUNCATED: %t\n", truncated)
	fmt.Fprintf(&sb, "LINE_RANGE: %d-%d\n", startLine, endLine)
	for i, line := range slice {
		fmt.Fprintf(&sb, "%d|%s\n", startLine+i, line)
	}
	if truncated {
		fmt.Fprintf(&sb, "\nNote: Results truncated to %d lines. Narrow the line range.\n", DefaultMaxReadLines)
	}
	return sb.String(), nil
}

func filepathToSlash(path string) string {
	return strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
}
