package sast

// extToLang maps file extensions to language names used in prompts.
var extToLang = map[string]string{
	".go":   "go",
	".py":   "python",
	".js":   "javascript",
	".mjs":  "javascript",
	".cjs":  "javascript",
	".jsx":  "javascript",
	".ts":   "typescript",
	".tsx":  "typescript",
	".java": "java",
	".rb":   "ruby",
	".php":  "php",
	".cs":   "csharp",
	".rs":   "rust",
	".c":    "c",
	".cpp":  "cpp",
	".h":    "c",
	".hpp":  "cpp",
	".kt":   "kotlin",
	".swift": "swift",
	".sh":   "bash",
	".bash": "bash",
}

// skipDirs are directory names that are never scanned.
var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".venv": true, "venv": true, ".tox": true,
	"target": true, ".gradle": true, "out": true,
}
