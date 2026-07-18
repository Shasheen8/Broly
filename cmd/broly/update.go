package main

import (
	"fmt"
	"os/exec"
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

			updateCmd := exec.Command(goBin, "install", module)
			if out, err := updateCmd.CombinedOutput(); err != nil {
				return fmt.Errorf("update failed: %s: %w", strings.TrimSpace(string(out)), err)
			}

			after := currentVersionInfo()
			if before.Version == after.Version {
				fmt.Printf("Already up to date: %s\n", after.Version)
			} else {
				fmt.Printf("Updated: %s -> %s\n", before.Version, after.Version)
			}

			if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
				fmt.Println("Make sure $(go env GOPATH)/bin is in your PATH.")
			}

			return nil
		},
	}
}
