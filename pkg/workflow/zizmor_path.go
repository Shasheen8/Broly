package workflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

const BundledZizmorPath = "/usr/local/bin/zizmor"

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
		if st, err := os.Stat(BundledZizmorPath); err == nil && !st.IsDir() {
			zizmorResolved = BundledZizmorPath
			return
		}
		zizmorResolved = "zizmor"
	})
	return zizmorResolved
}

func ZizmorAvailable() bool {
	path := ZizmorExecutable()
	if path == "zizmor" {
		_, err := exec.LookPath("zizmor")
		return err == nil
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
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
