package iac

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

const BundledCheckovPath = "/opt/checkov/bin/checkov"

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
		if st, err := os.Stat(BundledCheckovPath); err == nil && !st.IsDir() {
			checkovResolved = BundledCheckovPath
			return
		}
		checkovResolved = "checkov"
	})
	return checkovResolved
}

func CheckovAvailable() bool {
	path := CheckovExecutable()
	if path == "checkov" {
		_, err := exec.LookPath("checkov")
		return err == nil
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
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
