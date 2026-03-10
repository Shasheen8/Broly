// Package suppress implements inline finding suppression via source comments.
//
// A finding is suppressed when its line (or the line immediately above) contains:
//
//	// broly:ignore              — suppress any finding on this line
//	// broly:ignore <rule-id>   — suppress a specific rule only
//	# broly:ignore               — works for Python, Ruby, shell, etc.
package suppress

import (
	"bufio"
	"os"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

const marker = "broly:ignore"

// Filter removes findings whose source line carries a broly:ignore comment.
func Filter(findings []core.Finding) (filtered []core.Finding, count int) {
	lineCache := make(map[string][]string)

	for _, f := range findings {
		if f.FilePath == "" || f.StartLine < 1 {
			filtered = append(filtered, f)
			continue
		}
		lines := cachedLines(f.FilePath, lineCache)
		if isIgnored(lines, f) {
			count++
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered, count
}

func isIgnored(lines []string, f core.Finding) bool {
	for _, lineNum := range []int{f.StartLine, f.StartLine - 1} {
		if lineNum < 1 || lineNum > len(lines) {
			continue
		}
		lower := strings.ToLower(lines[lineNum-1])
		idx := strings.Index(lower, marker)
		if idx < 0 {
			continue
		}
		// Everything after "broly:ignore" on the same line.
		rest := strings.TrimSpace(lower[idx+len(marker):])
		if rest == "" {
			// bare broly:ignore — suppress everything on this line
			return true
		}
		// rule-specific: broly:ignore <rule-id>
		// strip any trailing comment characters
		ruleID := strings.Fields(rest)[0]
		if strings.EqualFold(ruleID, f.RuleID) {
			return true
		}
	}
	return false
}

func cachedLines(path string, cache map[string][]string) []string {
	if lines, ok := cache[path]; ok {
		return lines
	}
	f, err := os.Open(path)
	if err != nil {
		cache[path] = nil
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	cache[path] = lines
	return lines
}
