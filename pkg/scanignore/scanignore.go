package scanignore

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var ignoredDirNames = map[string]struct{}{
	".cache":        {},
	".git":          {},
	".gradle":       {},
	".hg":           {},
	".mypy_cache":   {},
	".next":         {},
	".nox":          {},
	".nuxt":         {},
	".parcel-cache": {},
	".pytest_cache": {},
	".ruff_cache":   {},
	".svn":          {},
	".tox":          {},
	".turbo":        {},
	".venv":         {},
	".yarn":         {},
	"__pycache__":   {},
	"build":         {},
	"coverage":      {},
	"dist":          {},
	"node_modules":  {},
	"out":           {},
	"target":        {},
	"vendor":        {},
	"venv":          {},
}

func IsIgnoredDirName(name string) bool {
	_, ok := ignoredDirNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func PathHasIgnoredDir(path string) bool {
	for _, part := range pathParts(path) {
		if IsIgnoredDirName(part) {
			return true
		}
	}
	return false
}

func RelativePathHasIgnoredDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return PathHasIgnoredDir(path)
	}
	return PathHasIgnoredDir(rel)
}

func FilterPaths(paths []string) []string {
	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		if PathHasIgnoredDir(path) {
			continue
		}
		filtered = append(filtered, path)
	}
	return filtered
}

func SkipDirRegex() *regexp.Regexp {
	names := make([]string, 0, len(ignoredDirNames))
	for name := range ignoredDirNames {
		names = append(names, regexp.QuoteMeta(name))
	}
	sort.Strings(names)
	return regexp.MustCompile(`(^|[\\/])(?:` + strings.Join(names, "|") + `)(?:[\\/]|$)`)
}

func pathParts(path string) []string {
	path = strings.TrimSpace(filepath.ToSlash(filepath.Clean(path)))
	if path == "" || path == "." {
		return nil
	}
	return strings.FieldsFunc(path, func(r rune) bool {
		return r == '/'
	})
}
