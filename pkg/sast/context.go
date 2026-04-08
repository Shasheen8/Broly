package sast

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultMaxContextFiles = 2
	defaultMaxContextBytes = 16 * 1024
)

var (
	importFromPattern   = regexp.MustCompile(`(?m)from\s+['"](\.[^'"]+)['"]`)
	requirePattern      = regexp.MustCompile(`(?m)require\(\s*['"](\.[^'"]+)['"]\s*\)`)
	goSingleImportMatch = regexp.MustCompile(`^\s*import\s+"([^"]+)"`)
	goBlockImportMatch  = regexp.MustCompile(`^\s*"([^"]+)"`)
)

func collectGoSliceFiles(index *repoIndex, root, path, content string, maxFiles int, maxBytes int) []sliceFile {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	current := filepath.Clean(path)
	remaining := maxBytes
	files := make([]sliceFile, 0, maxFiles)
	packageName := extractGoPackageName(content)
	seen := map[string]bool{current: true}

	for _, entry := range entries {
		if len(files) >= maxFiles || remaining <= 0 {
			break
		}
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}

		candidate := filepath.Join(dir, name)
		if filepath.Clean(candidate) == current {
			continue
		}

		if !pathWithinRoot(root, candidate) {
			continue
		}

		context, used, ok := loadContextFile(candidate, remaining)
		if !ok {
			continue
		}
		if packageName != "" && extractGoPackageName(context) != packageName {
			continue
		}

		files = append(files, sliceFile{
			Path:         candidate,
			RelativePath: relativeSlicePath(root, candidate),
			Language:     "go",
			Content:      context,
		})
		remaining -= used
		seen[filepath.Clean(candidate)] = true
	}

	for _, importPath := range extractGoImports(content) {
		if len(files) >= maxFiles || remaining <= 0 {
			break
		}
		importDir, ok := index.resolveLocalGoImport(importPath)
		if !ok {
			continue
		}
		importFiles, used := loadGoPackageSliceFiles(root, importDir, seen, maxFiles-len(files), remaining)
		files = append(files, importFiles...)
		remaining -= used
	}

	return files
}

func loadGoPackageSliceFiles(root, dir string, seen map[string]bool, remainingFiles int, remainingBytes int) ([]sliceFile, int) {
	if remainingFiles <= 0 || remainingBytes <= 0 {
		return nil, 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}
	files := make([]sliceFile, 0, remainingFiles)
	usedBytes := 0
	for _, entry := range entries {
		if len(files) >= remainingFiles || remainingBytes-usedBytes <= 0 {
			break
		}
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		candidate := filepath.Join(dir, name)
		if seen[filepath.Clean(candidate)] || !pathWithinRoot(root, candidate) {
			continue
		}
		context, used, ok := loadContextFile(candidate, remainingBytes-usedBytes)
		if !ok {
			continue
		}
		files = append(files, sliceFile{
			Path:         candidate,
			RelativePath: relativeSlicePath(root, candidate),
			Language:     "go",
			Content:      context,
		})
		usedBytes += used
		seen[filepath.Clean(candidate)] = true
	}
	return files, usedBytes
}

func collectJSImportSliceFiles(root, path, lang, content string, maxFiles int, maxBytes int) []sliceFile {
	remaining := maxBytes
	files := make([]sliceFile, 0, maxFiles)
	seen := make(map[string]bool)
	queue := resolveJSImportSpecifiers(root, filepath.Dir(path), lang, content, seen)

	for len(queue) > 0 {
		if len(files) >= maxFiles || remaining <= 0 {
			break
		}
		resolved := queue[0]
		queue = queue[1:]

		context, used, ok := loadContextFile(resolved, remaining)
		if !ok {
			continue
		}

		fileLang := detectContextLanguage(resolved)
		files = append(files, sliceFile{
			Path:         resolved,
			RelativePath: relativeSlicePath(root, resolved),
			Language:     fileLang,
			Content:      context,
		})
		remaining -= used
		queue = append(queue, resolveJSImportSpecifiers(root, filepath.Dir(resolved), fileLang, context, seen)...)
	}

	return files
}

func resolveJSImportSpecifiers(root, baseDir, lang, content string, seen map[string]bool) []string {
	specs := append(importFromPattern.FindAllStringSubmatch(content, -1), requirePattern.FindAllStringSubmatch(content, -1)...)
	if len(specs) == 0 {
		return nil
	}

	resolved := make([]string, 0, len(specs))
	for _, match := range specs {
		if len(match) < 2 {
			continue
		}
		path, ok := resolveJSImport(root, baseDir, match[1], lang)
		if !ok || seen[path] {
			continue
		}
		seen[path] = true
		resolved = append(resolved, path)
	}
	sort.Strings(resolved)
	return resolved
}

func resolveJSImport(root, baseDir, specifier, lang string) (string, bool) {
	candidate := filepath.Join(baseDir, specifier)
	extensions := []string{".ts", ".tsx", ".js", ".jsx"}
	if lang == "javascript" {
		extensions = []string{".js", ".jsx", ".ts", ".tsx"}
	}

	if resolved, ok := resolveCandidate(root, candidate); ok {
		return resolved, true
	}
	for _, ext := range extensions {
		if resolved, ok := resolveCandidate(root, candidate+ext); ok {
			return resolved, true
		}
	}
	for _, ext := range extensions {
		indexPath := filepath.Join(candidate, "index"+ext)
		if resolved, ok := resolveCandidate(root, indexPath); ok {
			return resolved, true
		}
	}

	return "", false
}

func detectContextLanguage(path string) string {
	if lang, ok := extToLang[strings.ToLower(filepath.Ext(path))]; ok {
		return lang
	}
	return ""
}

func extractGoImports(content string) []string {
	seen := make(map[string]bool)
	imports := make([]string, 0)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		var importPath string
		if match := goSingleImportMatch.FindStringSubmatch(line); len(match) >= 2 {
			importPath = match[1]
		} else if match := goBlockImportMatch.FindStringSubmatch(line); len(match) >= 2 {
			importPath = match[1]
		}
		if importPath == "" || seen[importPath] {
			continue
		}
		seen[importPath] = true
		imports = append(imports, importPath)
	}
	sort.Strings(imports)
	return imports
}

func loadContextFile(path string, remaining int) (string, int, bool) {
	if remaining <= 0 {
		return "", 0, false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, false
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, int64(remaining)))
	if err != nil {
		return "", 0, false
	}
	if len(data) == 0 {
		return "", 0, false
	}

	return string(data), len(data), true
}

func resolveCandidate(root, candidate string) (string, bool) {
	if !fileExists(candidate) {
		return "", false
	}
	resolved := candidate
	if symlinkPath, err := filepath.EvalSymlinks(candidate); err == nil {
		resolved = symlinkPath
	}
	if !pathWithinRoot(root, resolved) {
		return "", false
	}
	return resolved, true
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func pathWithinRoot(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rootAbs = filepath.Clean(rootAbs)
	candidateAbs = filepath.Clean(candidateAbs)
	if resolvedRoot, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = filepath.Clean(resolvedRoot)
	}
	if resolvedCandidate, err := filepath.EvalSymlinks(candidateAbs); err == nil {
		candidateAbs = filepath.Clean(resolvedCandidate)
	}
	if candidateAbs == rootAbs {
		return true
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func extractGoPackageName(content string) string {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "package" {
			return fields[1]
		}
	}
	return ""
}

func scanRoot(target string) string {
	info, err := os.Stat(target)
	if err == nil && info.IsDir() {
		return target
	}
	return filepath.Dir(target)
}
