package sast

import "strings"

// extToLang maps file extensions to language names used in prompts.
var extToLang = map[string]string{
	".go":         "go",
	".py":         "python",
	".js":         "javascript",
	".mjs":        "javascript",
	".cjs":        "javascript",
	".jsx":        "javascript",
	".ts":         "typescript",
	".tsx":        "typescript",
	".java":       "java",
	".rb":         "ruby",
	".php":        "php",
	".cs":         "csharp",
	".rs":         "rust",
	".c":          "c",
	".cpp":        "cpp",
	".h":          "c",
	".hpp":        "cpp",
	".kt":         "kotlin",
	".swift":      "swift",
	".sh":         "bash",
	".bash":       "bash",
	".dockerfile": "dockerfile",
}

// detectLangByName matches filenames that don't rely on extensions.
// Covers Dockerfile, Dockerfile.prod, Dockerfile-dev, Containerfile, and variants.
func detectLangByName(name string) (string, bool) {
	lower := strings.ToLower(name)

	// Dockerfile, Dockerfile.prod, Dockerfile-dev, etc.
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "dockerfile-") {
		return "dockerfile", true
	}

	// Containerfile (Podman/OCI standard) and variants
	if lower == "containerfile" || strings.HasPrefix(lower, "containerfile.") || strings.HasPrefix(lower, "containerfile-") {
		return "dockerfile", true
	}

	// Docker Compose: docker-compose.yml, docker-compose.prod.yml, compose.yml, etc.
	if strings.HasPrefix(lower, "docker-compose.") || strings.HasPrefix(lower, "compose.") {
		ext := lower[strings.LastIndex(lower, "."):]
		if ext == ".yml" || ext == ".yaml" {
			return "docker-compose", true
		}
	}

	return "", false
}

// skipDirs are directory names that are never scanned.
var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true,
	"target": true, ".gradle": true, "out": true,
}
