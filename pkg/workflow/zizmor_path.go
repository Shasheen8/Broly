package workflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/Shasheen8/Broly/pkg/toolinstall"
)

var (
	zizmorOnce     sync.Once
	zizmorResolved string
)

func ZizmorExecutable() string {
	zizmorOnce.Do(func() {
		if path, err := exec.LookPath("zizmor"); err == nil {
			zizmorResolved = path
			return
		}
		venvPath := filepath.Join(toolinstall.VenvBinDir(), "zizmor")
		if st, err := os.Stat(venvPath); err == nil && !st.IsDir() {
			zizmorResolved = venvPath
			return
		}
		zizmorResolved = "zizmor"
	})
	return zizmorResolved
}

func ZizmorAvailable() bool {
	return toolinstall.ToolAvailable("zizmor")
}

func SetZizmorExecutableForTest(path string) func() {
	prev := zizmorResolved
	zizmorOnce = sync.Once{}
	if path == "" {
		zizmorResolved = ""
	} else {
		zizmorResolved = filepath.Clean(path)
	}
	return func() {
		zizmorResolved = prev
		zizmorOnce = sync.Once{}
	}
}
