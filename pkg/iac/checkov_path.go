package iac

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/Shasheen8/Broly/pkg/toolinstall"
)

var (
	checkovOnce     sync.Once
	checkovResolved string
)

func CheckovExecutable() string {
	checkovOnce.Do(func() {
		if path, err := exec.LookPath("checkov"); err == nil {
			checkovResolved = path
			return
		}
		venvPath := filepath.Join(toolinstall.VenvBinDir(), "checkov")
		if st, err := os.Stat(venvPath); err == nil && !st.IsDir() {
			checkovResolved = venvPath
			return
		}
		checkovResolved = "checkov"
	})
	return checkovResolved
}

func CheckovAvailable() bool {
	return toolinstall.ToolAvailable("checkov")
}

func SetCheckovExecutableForTest(path string) func() {
	prev := checkovResolved
	checkovOnce = sync.Once{}
	if path == "" {
		checkovResolved = ""
	} else {
		checkovResolved = filepath.Clean(path)
	}
	return func() {
		checkovResolved = prev
		checkovOnce = sync.Once{}
	}
}
