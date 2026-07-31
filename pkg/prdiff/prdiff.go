// Package prdiff parses GitHub's per-file unified diff patches to tell whether a
// line was actually added or modified by a PR, rather than merely living in a file
// the PR touched.
package prdiff

import (
	"strconv"
	"strings"
)

// FileDiff holds the new-file line numbers one file's patch added or modified.
type FileDiff struct {
	AddedLines map[int]bool
}

// HasLine reports whether any line in [startLine, endLine] was added or modified.
// endLine < startLine is treated as a single-line range.
func (d *FileDiff) HasLine(startLine, endLine int) bool {
	if d == nil || startLine < 1 {
		return false
	}
	if endLine < startLine {
		endLine = startLine
	}
	for line := startLine; line <= endLine; line++ {
		if d.AddedLines[line] {
			return true
		}
	}
	return false
}

var hunkHeaderPrefix = "@@ -"

// ParsePatch returns the new-file line numbers a GitHub "patch" field added or
// modified. That field contains only hunk bodies, no file headers.
func ParsePatch(patch string) *FileDiff {
	diff := &FileDiff{AddedLines: map[int]bool{}}
	if strings.TrimSpace(patch) == "" {
		return diff
	}

	newLine := 0
	inHunk := false
	for line := range strings.SplitSeq(patch, "\n") {
		if strings.HasPrefix(line, hunkHeaderPrefix) {
			start, ok := parseHunkNewStart(line)
			if !ok {
				inHunk = false
				continue
			}
			newLine = start
			inHunk = true
			continue
		}
		if !inHunk || line == "" {
			continue
		}
		switch line[0] {
		case '+':
			diff.AddedLines[newLine] = true
			newLine++
		case '-':
			// old-file-only line; new-file line counter does not advance.
		case '\\':
			// "\ No newline at end of file" marker; ignore.
		default:
			newLine++
		}
	}
	return diff
}

// parseHunkNewStart reads the new-file start from "@@ -old,n +new,n @@".
func parseHunkNewStart(header string) (int, bool) {
	_, rest, ok := strings.Cut(header, "+")
	if !ok {
		return 0, false
	}
	rest, _, _ = strings.Cut(rest, " ")
	numPart, _, _ := strings.Cut(rest, ",")
	n, err := strconv.Atoi(numPart)
	if err != nil {
		return 0, false
	}
	return n, true
}
