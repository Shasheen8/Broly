package container

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/Shasheen8/Broly/pkg/scanignore"
)

// Prevents an attacker-controlled file from forcing a huge allocation.
const MaxDockerfileBytes = 1 << 20

func IsDockerfilePath(rel string) bool {
	base := filepath.Base(rel)
	if base == "Dockerfile" || base == "Containerfile" {
		return true
	}
	lower := strings.ToLower(base)
	return strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile")
}

func IsComposePath(rel string) bool {
	lower := strings.ToLower(filepath.Base(rel))
	switch lower {
	case "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml":
		return true
	}
	return false
}

// IsContainerSpecPath returns true for any file we can extract base images from.
func IsContainerSpecPath(rel string) bool {
	return IsDockerfilePath(rel) || IsComposePath(rel)
}

// ImagesFromFile dispatches to the right parser based on the file's name.
func ImagesFromFile(rel, content string) []string {
	switch {
	case IsDockerfilePath(rel):
		return ParseImages(content)
	case IsComposePath(rel):
		return ParseComposeImages(content)
	}
	return nil
}

// ParseImages returns FROM image refs, skipping local stages, scratch, and
// ARG-templated values that can't be resolved without build context.
func ParseImages(content string) []string {
	var images []string
	stages := make(map[string]bool)
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		fields = fields[1:]
		for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		img := fields[0]
		recordStage := func() {
			if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
				stages[fields[2]] = true
			}
		}
		if stages[img] || strings.EqualFold(img, "scratch") || strings.Contains(img, "$") {
			recordStage()
			continue
		}
		images = append(images, img)
		recordStage()
	}
	return images
}

// ParseComposeImages returns the images referenced from each service in a
// Docker Compose file. Skips services that use `build:` (their Dockerfile is
// scanned separately) and templated values containing ${…}.
func ParseComposeImages(content string) []string {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
			Build any    `yaml:"build"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var images []string
	for _, svc := range doc.Services {
		if svc.Build != nil || svc.Image == "" || strings.Contains(svc.Image, "$") {
			continue
		}
		if seen[svc.Image] {
			continue
		}
		seen[svc.Image] = true
		images = append(images, svc.Image)
	}
	return images
}

// ReadDockerfile rejects paths that escape dir and caps the read at MaxDockerfileBytes.
func ReadDockerfile(dir, rel string) (string, bool) {
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", false
	}
	f, err := os.Open(filepath.Join(dir, clean))
	if err != nil {
		return "", false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxDockerfileBytes))
	if err != nil {
		return "", false
	}
	return string(data), true
}

// FindContainerSpecs walks dir and returns relative paths of Dockerfiles,
// Containerfiles, and Compose files (skipping vendored / ignored directories).
func FindContainerSpecs(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if path != dir && scanignore.IsIgnoredDirName(name) {
				return filepath.SkipDir
			}
			return nil
		}
		if !IsContainerSpecPath(name) {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out
}
