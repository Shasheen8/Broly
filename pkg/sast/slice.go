package sast

import (
	"path/filepath"
	"sort"
)

type sliceFile struct {
	Path         string
	RelativePath string
	Language     string
	Content      string
}

type analysisSlice struct {
	Root       string
	Primary    sliceFile
	Supporting []sliceFile
}

func buildAnalysisSlice(index *repoIndex, root, path, lang, content string, maxFiles int, maxBytes int) (analysisSlice, error) {
	slice := analysisSlice{
		Root: root,
		Primary: sliceFile{
			Path:         path,
			RelativePath: relativeSlicePath(root, path),
			Language:     lang,
			Content:      content,
		},
	}
	if maxFiles <= 0 || maxBytes <= 0 {
		return slice, nil
	}
	if index == nil {
		index = newRepoIndex(root)
	}

	switch lang {
	case "go":
		slice.Supporting = collectGoSliceFiles(index, root, path, content, maxFiles, maxBytes)
	case "javascript", "typescript":
		slice.Supporting = collectJSImportSliceFiles(root, path, lang, content, maxFiles, maxBytes)
	}

	sort.Slice(slice.Supporting, func(i, j int) bool {
		return slice.Supporting[i].RelativePath < slice.Supporting[j].RelativePath
	})
	return slice, nil
}

func relativeSlicePath(root, path string) string {
	rootPath := filepath.Clean(root)
	candidatePath := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(rootPath); err == nil {
		rootPath = filepath.Clean(resolved)
	}
	if resolved, err := filepath.EvalSymlinks(candidatePath); err == nil {
		candidatePath = filepath.Clean(resolved)
	}
	rel, err := filepath.Rel(rootPath, candidatePath)
	if err != nil {
		return filepath.ToSlash(filepath.Base(candidatePath))
	}
	return filepath.ToSlash(rel)
}
