package sast

import "testing"

func TestDetectLangByName(t *testing.T) {
	tests := []struct {
		name     string
		wantLang string
		wantOK   bool
	}{
		// Dockerfile variants
		{"Dockerfile", "dockerfile", true},
		{"dockerfile", "dockerfile", true},
		{"DOCKERFILE", "dockerfile", true},
		{"Dockerfile.prod", "dockerfile", true},
		{"Dockerfile.dev", "dockerfile", true},
		{"Dockerfile.staging", "dockerfile", true},
		{"Dockerfile-prod", "dockerfile", true},
		{"Dockerfile-dev", "dockerfile", true},
		{"Dockerfile-alpine", "dockerfile", true},

		// Containerfile variants (Podman/OCI)
		{"Containerfile", "dockerfile", true},
		{"containerfile", "dockerfile", true},
		{"Containerfile.prod", "dockerfile", true},
		{"Containerfile-dev", "dockerfile", true},

		// Docker Compose variants
		{"docker-compose.yml", "docker-compose", true},
		{"docker-compose.yaml", "docker-compose", true},
		{"docker-compose.prod.yml", "docker-compose", true},
		{"docker-compose.override.yaml", "docker-compose", true},
		{"compose.yml", "docker-compose", true},
		{"compose.yaml", "docker-compose", true},
		{"compose.prod.yml", "docker-compose", true},

		// Extension-based (handled by extToLang, not this function)
		{"app.dockerfile", "", false},

		// Non-matches
		{"docker-compose.env", "", false},
		{"compose.json", "", false},
		{".dockerignore", "", false},
		{"main.go", "", false},
		{"Makefile", "", false},
		{"README.md", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lang, ok := detectLangByName(tt.name)
			if ok != tt.wantOK {
				t.Errorf("detectLangByName(%q) ok = %v, want %v", tt.name, ok, tt.wantOK)
			}
			if lang != tt.wantLang {
				t.Errorf("detectLangByName(%q) lang = %q, want %q", tt.name, lang, tt.wantLang)
			}
		})
	}
}

func TestExtToLangDockerfile(t *testing.T) {
	lang, ok := extToLang[".dockerfile"]
	if !ok || lang != "dockerfile" {
		t.Errorf("extToLang[.dockerfile] = %q, %v; want \"dockerfile\", true", lang, ok)
	}
}
