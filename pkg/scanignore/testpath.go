package scanignore

import (
	"path/filepath"
	"regexp"
	"strings"
)

var obviousTestCredential = regexp.MustCompile(`(?i)(test|mock|example|fake|dummy|placeholder|from-disk|not-real|changeme|your[_-]?key|insert[_-]?here|xxx+|sample|fixture)`)

func IsTestFile(path string) bool {
	p := filepath.ToSlash(strings.TrimSpace(path))
	if p == "" {
		return false
	}
	lower := strings.ToLower(p)
	base := strings.ToLower(filepath.Base(p))

	for _, part := range strings.Split(lower, "/") {
		switch part {
		case "tests", "__tests__", "fixtures", "testdata", "mocks":
			return true
		}
	}

	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.HasSuffix(base, ".test.ts"),
		strings.HasSuffix(base, ".test.tsx"),
		strings.HasSuffix(base, ".test.js"),
		strings.HasSuffix(base, ".test.jsx"),
		strings.HasSuffix(base, ".spec.ts"),
		strings.HasSuffix(base, ".spec.tsx"),
		strings.HasSuffix(base, ".spec.js"),
		strings.HasSuffix(base, ".spec.jsx"),
		strings.HasSuffix(base, "_test.py"),
		strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"):
		return true
	}
	return false
}

func IsObviousTestCredentialLiteral(literal string) bool {
	literal = strings.TrimSpace(literal)
	if literal == "" {
		return false
	}
	if len(literal) < 32 && obviousTestCredential.MatchString(literal) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(literal), "sk-test") ||
		strings.HasPrefix(strings.ToLower(literal), "sk-mock") {
		return true
	}
	return false
}
