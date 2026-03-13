// Package secrets adapts Titus's engine to Broly's core.Scanner interface.
package secrets

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	titus "github.com/praetorian-inc/titus"

	"github.com/Shasheen8/Broly/pkg/core"
)

var secretsSkipDirs = map[string]bool{
	"vendor": true, "node_modules": true, ".git": true,
	"dist": true, "build": true, "__pycache__": true,
	".venv": true, "venv": true, "target": true,
}

type SecretsScanner struct {
	scanner          *titus.Scanner
	validator        *AIValidator
	disableRedaction bool
	maxFileSize      int64
	excludePaths     map[string]bool
}

func NewSecretsScanner() *SecretsScanner {
	return &SecretsScanner{}
}

func (s *SecretsScanner) Name() string        { return "secrets" }
func (s *SecretsScanner) Type() core.ScanType { return core.ScanTypeSecrets }

func (s *SecretsScanner) Init(cfg *core.Config) error {
	s.disableRedaction = cfg.DisableRedaction
	s.maxFileSize = cfg.MaxFileSize
	if s.maxFileSize == 0 {
		s.maxFileSize = 100 * 1024 * 1024 // 100MB default
	}

	s.excludePaths = make(map[string]bool, len(cfg.ExcludePaths))
	for _, p := range cfg.ExcludePaths {
		s.excludePaths[p] = true
	}

	opts := []titus.Option{
		titus.WithContextLines(0),
	}

	if cfg.ValidateSecrets {
		opts = append(opts, titus.WithValidation())
		if cfg.Workers > 0 {
			opts = append(opts, titus.WithValidationWorkers(cfg.Workers))
		}
	}

	if cfg.SecretsRulesDir != "" {
		rules, err := titus.LoadRulesFromFile(cfg.SecretsRulesDir)
		if err != nil {
			return fmt.Errorf("load secrets rules: %w", err)
		}
		opts = append(opts, titus.WithRules(rules))
	}

	scanner, err := titus.NewScanner(opts...)
	if err != nil {
		return fmt.Errorf("init secrets scanner: %w", err)
	}
	s.scanner = scanner

	if cfg.AIFilterSecrets {
		s.validator = newAIValidator(cfg.AIModel)
		if s.validator == nil {
			fmt.Fprintln(os.Stderr, "warning: TOGETHER_API_KEY not set — AI secrets filtering disabled")
		}
	}

	return nil
}

func (s *SecretsScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	for _, target := range paths {
		if ctx.Err() != nil {
			return nil
		}
		if err := s.scanPath(ctx, target, findings); err != nil {
			fmt.Fprintf(os.Stderr, "warning: secrets scan of %s: %v\n", target, err)
		}
	}

	return nil
}

func (s *SecretsScanner) scanPath(ctx context.Context, root string, findings chan<- core.Finding) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return filepath.SkipAll
		}

		name := d.Name()
		if s.excludePaths[name] || s.excludePaths[path] {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if secretsSkipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > s.maxFileSize {
			return nil
		}

		matches, err := s.scanner.ScanFile(path)
		if err != nil {
			return nil
		}

		var batch []core.Finding
		for _, m := range matches {
			redacted := redact(m.Snippet.Matching)
			snippet := redacted
			if s.disableRedaction {
				snippet = string(m.Snippet.Matching)
			}

			f := core.Finding{
				Type:        core.ScanTypeSecrets,
				RuleID:      m.RuleID,
				RuleName:    m.RuleName,
				Severity:    core.SeverityHigh,
				Title:       "Secret detected: " + m.RuleName,
				Description: fmt.Sprintf("Potential secret matching rule %q", m.RuleName),
				FilePath:    path,
				StartLine:   int(m.Location.Source.Start.Line),
				EndLine:     int(m.Location.Source.End.Line),
				Snippet:     snippet,
				Redacted:    redacted,
				Tags:        []string{"secrets"},
				Timestamp:   time.Now(),
			}
			if m.ValidationResult != nil {
				f.Tags = append(f.Tags, string(m.ValidationResult.Status))
			}
			f.ComputeFingerprint()
			batch = append(batch, f)
		}

		if s.validator != nil && len(batch) > 0 {
			batch = s.validator.filterBatch(ctx, batch)
		}

		for _, f := range batch {
			select {
			case findings <- f:
			case <-ctx.Done():
				return filepath.SkipAll
			}
		}

		return nil
	})
}

func (s *SecretsScanner) Close() error {
	if s.scanner != nil {
		return s.scanner.Close()
	}
	return nil
}

func redact(b []byte) string {
	s := string(b)
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// ValidateRules verifies that builtin secrets rules load successfully.
func ValidateRules() (int, error) {
	rules, err := titus.LoadBuiltinRules()
	if err != nil {
		return 0, err
	}
	return len(rules), nil
}
