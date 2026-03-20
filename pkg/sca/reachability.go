package sca

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

const reachabilityPrompt = `You are a security expert analyzing whether a vulnerable dependency is actually reachable in source code.

Vulnerability: %s
Package: %s@%s
Description: %s

The following source files import this package:

%s

Based solely on the code above, determine:
1. Is the specific vulnerable functionality actually imported and called?
2. Are there code paths that could trigger the vulnerability in practice?

Focus on what is explicitly present in the code — do not speculate about code not shown.

Respond with exactly two lines:
REACHABILITY: REACHABLE or UNREACHABLE or UNKNOWN
REASON: One sentence explaining which function or pattern is (or is not) called.`

type reachabilityResult struct {
	status string // REACHABLE, UNREACHABLE, UNKNOWN
	reason string
}

type AIReachability struct {
	client *ai.Client
}

func newAIReachability(model string) *AIReachability {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &AIReachability{client: c}
}

func (r *AIReachability) analyze(ctx context.Context, f core.Finding, scanPaths []string) reachabilityResult {
	files := findImportingFiles(f.PackageName, f.Ecosystem, scanPaths)
	if len(files) == 0 {
		return reachabilityResult{status: "UNKNOWN", reason: "No source files importing this package were found in scanned paths."}
	}

	filesContent := buildFilesContent(files, 300) // max 300 lines per file
	prompt := fmt.Sprintf(reachabilityPrompt,
		f.RuleID,
		f.PackageName, f.PackageVersion,
		f.Description,
		filesContent,
	)

	resp, err := r.client.Complete(ctx, prompt, 512)
	if err != nil {
		return reachabilityResult{status: "UNKNOWN", reason: "AI analysis failed: " + err.Error()}
	}

	return parseReachability(resp)
}

func parseReachability(resp string) reachabilityResult {
	res := reachabilityResult{status: "UNKNOWN"}
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "REACHABILITY:") {
			res.status = strings.TrimSpace(line[len("REACHABILITY:"):])
			res.status = strings.ToUpper(res.status)
		} else if strings.HasPrefix(upper, "REASON:") {
			res.reason = strings.TrimSpace(line[len("REASON:"):])
		}
	}
	return res
}

func annotate(f *core.Finding, res reachabilityResult) {
	switch res.status {
	case "REACHABLE":
		f.Tags = append(f.Tags, "reachable")
		f.Confidence = "high"
	case "UNREACHABLE":
		f.Tags = append(f.Tags, "unreachable")
		f.Confidence = "low"
		// Downgrade severity one level (critical→high, high→medium, etc.)
		if f.Severity > core.SeverityInfo {
			f.Severity--
		}
		f.Description = "[Unreachable] " + f.Description
	default:
		f.Tags = append(f.Tags, "reachability-unknown")
	}
	if res.reason != "" {
		f.Description += " | " + res.reason
	}
}

func findImportingFiles(pkgName string, ecosystem string, scanPaths []string) []string {
	patterns := importPatterns(pkgName, ecosystem)
	if len(patterns) == 0 {
		return nil
	}

	var found []string
	seen := make(map[string]bool)

	for _, root := range scanPaths {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if len(found) >= 5 {
				return filepath.SkipAll
			}
			if d.IsDir() {
				return nil
			}
			if seen[path] {
				return nil
			}
			for _, p := range importSkipDirs {
				if strings.Contains(path, string(filepath.Separator)+p+string(filepath.Separator)) {
					return nil
				}
			}
			if fileContainsAny(path, patterns) {
				seen[path] = true
				found = append(found, path)
			}
			return nil
		})
	}
	return found
}

var importSkipDirs = []string{"vendor", "node_modules", ".git", "dist", "build", "__pycache__"}

func importPatterns(pkgName, ecosystem string) []string {
	eco := strings.ToLower(ecosystem)
	name := pkgName

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	switch {
	case strings.Contains(eco, "go"):
		return []string{`"` + pkgName + `"`, `"` + name + `"`}
	case strings.Contains(eco, "pypi") || strings.Contains(eco, "python"):
		return []string{"import " + name, "from " + name}
	case strings.Contains(eco, "npm") || strings.Contains(eco, "javascript") || strings.Contains(eco, "node"):
		return []string{`require('` + name + `')`, `require("` + name + `")`, `from '` + name, `from "` + name}
	case strings.Contains(eco, "maven") || strings.Contains(eco, "java"):
		return []string{"import " + strings.ReplaceAll(pkgName, "/", ".")}
	case strings.Contains(eco, "rubygems") || strings.Contains(eco, "ruby"):
		return []string{`require '` + name + `'`, `require "` + name + `"`}
	case strings.Contains(eco, "cargo") || strings.Contains(eco, "rust"):
		return []string{"use " + name + "::", "extern crate " + name}
	default:
		return []string{name}
	}
}

func fileContainsAny(path string, patterns []string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		for _, p := range patterns {
			if strings.Contains(line, p) {
				return true
			}
		}
	}
	return false
}

func buildFilesContent(files []string, maxLines int) string {
	var sb strings.Builder
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) > maxLines {
			lines = lines[:maxLines]
		}
		fmt.Fprintf(&sb, "--- %s ---\n%s\n\n", path, strings.Join(lines, "\n"))
	}
	return sb.String()
}
