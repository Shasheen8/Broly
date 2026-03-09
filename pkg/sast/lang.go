package sast

import (
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

var extToLang = map[string]string{
	".go":  "go",
	".py":  "python",
	".js":  "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
	".jsx": "javascript",
}

var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true,
}

func getLang(name string) *sitter.Language {
	switch name {
	case "go":
		return golang.GetLanguage()
	case "python":
		return python.GetLanguage()
	case "javascript":
		return javascript.GetLanguage()
	default:
		return nil
	}
}
