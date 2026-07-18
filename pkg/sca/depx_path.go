package sca

import (
	"os"
	"os/exec"
)

const BundledDepxPath = "/usr/local/bin/depx"

var depxExecutable = BundledDepxPath

func DepxAvailable() bool {
	if st, err := os.Stat(depxExecutable); err == nil && !st.IsDir() {
		return true
	}
	path, err := exec.LookPath("depx")
	if err != nil {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func resolveDepxExecutable() string {
	if st, err := os.Stat(depxExecutable); err == nil && !st.IsDir() {
		return depxExecutable
	}
	if path, err := exec.LookPath("depx"); err == nil {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path
		}
	}
	return depxExecutable
}

func SetDepxExecutableForTest(path string) func() {
	prev := depxExecutable
	if path == "" {
		depxExecutable = BundledDepxPath
	} else {
		depxExecutable = path
	}
	return func() { depxExecutable = prev }
}
