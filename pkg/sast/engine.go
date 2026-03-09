// Package sast provides SAST scanning. Phase 2: tree-sitter AST-based pattern matching.
package sast

import (
	"context"

	"github.com/Shasheen8/Broly/pkg/core"
)

type SASTScanner struct {
	rulesDir  string
	languages []string
}

func NewSASTScanner() *SASTScanner {
	return &SASTScanner{}
}

func (s *SASTScanner) Name() string       { return "sast" }
func (s *SASTScanner) Type() core.ScanType { return core.ScanTypeSAST }

func (s *SASTScanner) Init(cfg *core.Config) error {
	s.rulesDir = cfg.SASTRulesDir
	s.languages = cfg.Languages
	return nil
}

func (s *SASTScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)
	return nil
}

func (s *SASTScanner) Close() error { return nil }
