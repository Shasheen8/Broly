package reposearch

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	ToolFileRead   = "repo_file_read"
	ToolCodeSearch = "repo_code_search"
	ToolFindFiles  = "repo_find_files"
)

func (r *Repo) Execute(ctx context.Context, tool string, args map[string]string) (string, error) {
	switch strings.TrimSpace(tool) {
	case ToolFileRead:
		start, end := 0, 0
		if v := strings.TrimSpace(args["start_line"]); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return "", fmt.Errorf("invalid start_line: %w", err)
			}
			start = n
		}
		if v := strings.TrimSpace(args["end_line"]); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return "", fmt.Errorf("invalid end_line: %w", err)
			}
			end = n
		}
		return r.FileRead(ctx, args["path"], start, end)
	case ToolCodeSearch:
		var patterns []string
		if p := strings.TrimSpace(args["file_patterns"]); p != "" {
			patterns = strings.Split(p, ",")
		}
		return r.CodeSearch(ctx, args["query"], patterns)
	case ToolFindFiles:
		return r.FindFiles(ctx, args["pattern"])
	default:
		return "", fmt.Errorf("unknown tool %q", tool)
	}
}

func ToolDescriptions() string {
	return strings.TrimSpace(`
Available tools (request with TOOL: <name> key=value ...):

repo_file_read path=<repo-relative-path> [start_line=N] [end_line=N]
  Read file contents with optional line range (max 500 lines).

repo_code_search query=<text> [file_patterns=*.py,*.go]
  Search repository text. Uses git grep when available.

repo_find_files pattern=<substring>
  Find tracked files whose basename contains the pattern.
`)
}
