package workflow

import (
	"path/filepath"
	"strings"
)

func isWorkflowDefinitionPath(p string) bool {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, ".github/workflows/") {
		return true
	}
	switch filepath.Base(p) {
	case "action.yml", "action.yaml":
		return true
	default:
		return false
	}
}

func TouchesWorkflowDefinitions(paths []string) bool {
	for _, p := range paths {
		if isWorkflowDefinitionPath(p) {
			return true
		}
	}
	return false
}

func ChangedDefinitionPaths(paths []string) []string {
	return uniqueScanRoots(filterWorkflowDefinitionPaths(paths))
}

func filterWorkflowDefinitionPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if isWorkflowDefinitionPath(p) {
			out = append(out, strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
		}
	}
	return out
}

func uniqueScanRoots(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
