package workflow

import (
	"context"
	"fmt"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/toolinstall"
)

type WorkflowScanner struct{}

func NewWorkflowScanner() *WorkflowScanner { return &WorkflowScanner{} }

func (s *WorkflowScanner) Name() string        { return "workflow" }
func (s *WorkflowScanner) Type() core.ScanType { return core.ScanTypeWorkflow }

func (s *WorkflowScanner) Init(_ *core.Config) error {
	if !ZizmorAvailable() {
		path, err := toolinstall.EnsureTool("zizmor", "zizmor")
		if err != nil {
			return err
		}
		zizmorResolved = path
	}
	return nil
}

func (s *WorkflowScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	for _, root := range uniqueScanRoots(paths) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		parsed, err := runZizmor(ctx, root)
		if err != nil {
			return fmt.Errorf("workflow scan %s: %w", root, err)
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

func (s *WorkflowScanner) Close() error { return nil }
