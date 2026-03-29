package container

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJoinUnderRootRejectsTraversal(t *testing.T) {
	root := t.TempDir()

	if _, ok := joinUnderRoot(root, "../escape"); ok {
		t.Fatalf("expected parent traversal to be rejected")
	}
	if _, ok := joinUnderRoot(root, "/abs/path"); ok {
		t.Fatalf("expected absolute path to be rejected")
	}
	if full, ok := joinUnderRoot(root, "safe/package-lock.json"); !ok || full == "" {
		t.Fatalf("expected safe relative path to be accepted")
	}
}

func TestApplyOpaqueWhiteoutRemovesTrackedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	appDir := filepath.Join(tmpDir, "app")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		t.Fatalf("mkdir app dir: %v", err)
	}
	keepPath := filepath.Join(tmpDir, "keep.lock")
	removeA := filepath.Join(appDir, "package-lock.json")
	removeB := filepath.Join(appDir, "go.sum")
	for _, path := range []string{keepPath, removeA, removeB} {
		if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	results := []lockfileResult{
		{files: map[string]bool{
			"app/package-lock.json": true,
			"app/go.sum":            true,
			"keep.lock":             true,
		}},
	}

	applyOpaqueWhiteout(tmpDir, "app", results)

	for _, path := range []string{removeA, removeB} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, got err=%v", path, err)
		}
	}
	if _, err := os.Stat(keepPath); err != nil {
		t.Fatalf("expected keep file to remain: %v", err)
	}
	if results[0].files["app/package-lock.json"] || results[0].files["app/go.sum"] {
		t.Fatalf("expected opaque whiteout to remove tracked files in directory")
	}
	if !results[0].files["keep.lock"] {
		t.Fatalf("expected unrelated tracked file to remain")
	}
}
