package scanignore

import "testing"

func TestPathHasIgnoredDir(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"node_modules/pkg/index.js", true},
		{"src/.venv/lib/token.py", true},
		{"services/api/vendor/github.com/pkg/mod.go", true},
		{"src/package-lock.json", false},
		{"vendor.go", false},
		{"src/builders/main.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := PathHasIgnoredDir(tt.path); got != tt.want {
				t.Fatalf("PathHasIgnoredDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestFilterPathsKeepsManifestsOutsideIgnoredDirs(t *testing.T) {
	paths := []string{
		"package-lock.json",
		"node_modules/pkg/package-lock.json",
		"src/go.mod",
		"vendor/module/go.mod",
	}
	got := FilterPaths(paths)
	want := []string{"package-lock.json", "src/go.mod"}

	if len(got) != len(want) {
		t.Fatalf("FilterPaths returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("FilterPaths returned %v, want %v", got, want)
		}
	}
}

func TestSkipDirRegex(t *testing.T) {
	re := SkipDirRegex()
	for _, path := range []string{"node_modules", "src/node_modules", `src\node_modules`, "src/.pytest_cache"} {
		if !re.MatchString(path) {
			t.Fatalf("SkipDirRegex did not match %q", path)
		}
	}
	for _, path := range []string{"src/package-lock.json", "src/vendor.go", "src/builders"} {
		if re.MatchString(path) {
			t.Fatalf("SkipDirRegex matched %q", path)
		}
	}
}
