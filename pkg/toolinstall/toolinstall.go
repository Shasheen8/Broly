package toolinstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	cacheDir   string
	cacheOnce  sync.Once
	venvBinDir string
)

// cacheBase returns the broly cache directory (~/.cache/broly on Unix).
func cacheBase() string {
	cacheOnce.Do(func() {
		if dir, err := os.UserCacheDir(); err == nil && dir != "" {
			cacheDir = filepath.Join(dir, "broly")
		} else {
			home, _ := os.UserHomeDir()
			cacheDir = filepath.Join(home, ".cache", "broly")
		}
		os.MkdirAll(cacheDir, 0o755)
	})
	return cacheDir
}

// VenvBinDir returns the path to the venv's bin directory.
func VenvBinDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(cacheBase(), "venv", "Scripts")
	}
	return filepath.Join(cacheBase(), "venv", "bin")
}

func venvPython() string {
	return filepath.Join(VenvBinDir(), "python3")
}

func venvPip() string {
	return filepath.Join(VenvBinDir(), "pip")
}

// ensureVenv creates a Python venv in ~/.cache/broly/venv if it doesn't exist.
func ensureVenv() error {
	if st, err := os.Stat(venvPython()); err == nil && !st.IsDir() {
		return nil
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
		if err != nil {
			return fmt.Errorf("python not found — install Python 3 to auto-install scanning tools")
		}
	}
	cmd := exec.Command(python, "-m", "venv", filepath.Join(cacheBase(), "venv"))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create venv: %s: %w", string(out), err)
	}
	return nil
}

// EnsureTool checks PATH first, then the broly venv. If the tool is not found
// in either, it creates the venv (if needed) and pip-installs the package.
// Returns the path to the tool binary, or an error if installation fails.
func EnsureTool(tool, pipPackage string) (string, error) {
	if path, err := exec.LookPath(tool); err == nil {
		return path, nil
	}

	venvToolPath := filepath.Join(VenvBinDir(), tool)
	if st, err := os.Stat(venvToolPath); err == nil && !st.IsDir() {
		return venvToolPath, nil
	}

	if err := ensureVenv(); err != nil {
		return "", err
	}

	fmt.Fprintf(os.Stderr, "  installing %s...\n", pipPackage)
	cmd := exec.Command(venvPip(), "install", "--quiet", pipPackage)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("pip install %s: %s: %w", pipPackage, string(out), err)
	}

	if st, err := os.Stat(venvToolPath); err == nil && !st.IsDir() {
		return venvToolPath, nil
	}
	return "", fmt.Errorf("%s not found after installation", tool)
}

// ToolAvailable checks if a tool is available on PATH or in the broly venv.
// It does NOT auto-install — use EnsureTool for that.
func ToolAvailable(tool string) bool {
	if _, err := exec.LookPath(tool); err == nil {
		return true
	}
	venvToolPath := filepath.Join(VenvBinDir(), tool)
	st, err := os.Stat(venvToolPath)
	return err == nil && !st.IsDir()
}
