package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update broly to the latest version",
		Long: `Reinstall broly from the latest release using go install.

Requires Go to be installed on the system.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			before := currentVersionInfo()

			goBin, err := exec.LookPath("go")
			if err != nil {
				return fmt.Errorf("go not found in PATH - install Go from https://go.dev/dl/")
			}

			module := "github.com/Shasheen8/Broly/cmd/broly@latest"
			fmt.Printf("Updating broly (%s)...\n", before.Version)

			installCmd := exec.Command(goBin, "install", module)
			if out, err := installCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("update failed: %s: %w", strings.TrimSpace(string(out)), err)
			}

			gopath, err := exec.Command(goBin, "env", "GOPATH").Output()
			if err != nil {
				gopath = []byte("")
			}
			brolyBin := filepath.Join(strings.TrimSpace(string(gopath)), "bin", "broly")
			if runtime.GOOS == "windows" {
				brolyBin += ".exe"
			}

			afterVersion := before.Version
			versionOut, err := exec.Command(brolyBin, "version").Output()
			if err == nil {
				afterVersion = parseVersionOutput(string(versionOut))
			}

			if before.Version == afterVersion {
				fmt.Printf("Already up to date: %s\n", afterVersion)
			} else {
				fmt.Printf("Updated: %s -> %s\n", before.Version, afterVersion)
			}

			if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
				fmt.Println("Make sure $(go env GOPATH)/bin is in your PATH.")
			}

			return nil
		},
	}
}

func parseVersionOutput(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "version:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "version:"))
		}
	}
	return ""
}