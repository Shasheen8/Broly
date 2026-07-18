package iac

import (
	"context"
	"fmt"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/toolinstall"
)

type IaCScanner struct{}

func NewIaCScanner() *IaCScanner { return &IaCScanner{} }

func (s *IaCScanner) Name() string        { return "iac" }
func (s *IaCScanner) Type() core.ScanType { return core.ScanTypeIaC }

func (s *IaCScanner) Init(_ *core.Config) error {
	if !CheckovAvailable() {
		path, err := toolinstall.EnsureTool("checkov", "checkov")
		if err != nil {
			return err
		}
		checkovResolved = path
	}
	return nil
}

func (s *IaCScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	for _, root := range uniqueScanRoots(paths) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		parsed, err := runCheckov(ctx, root, defaultFrameworks)
		if err != nil {
			return fmt.Errorf("iac scan %s: %w", root, err)
		}
		for _, f := range parsed {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}

func (s *IaCScanner) Close() error { return nil }
