package suppress

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

const marker = "broly:ignore"

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
		rest := strings.TrimSpace(lower[idx+len(marker):])
		if rest == "" {
			return true
		}
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
	sc.Buffer(make([]byte, 0, 256*1024), 1024*1024) // handle lines up to 1MB
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if sc.Err() != nil {
		// Partial read — cache what we got, suppression may miss lines past the break.
		fmt.Fprintf(os.Stderr, "warning: partial read of %s for inline suppression: %v\n", path, sc.Err())
	}
	cache[path] = lines
	return lines
}
