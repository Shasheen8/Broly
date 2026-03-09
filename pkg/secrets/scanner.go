// Package secrets adapts Poltergeist's engine to Broly's core.Scanner interface.
package secrets

import (
	"context"
	"fmt"
	"os"
	"time"

	poltergeist "github.com/ghostsecurity/poltergeist/v2/pkg"

	"github.com/Shasheen8/Broly/pkg/core"
)

type SecretsScanner struct {
	scanner          *poltergeist.Scanner
	disableRedaction bool
}

func NewSecretsScanner() *SecretsScanner {
	return &SecretsScanner{}
}

func (s *SecretsScanner) Name() string       { return "secrets" }
func (s *SecretsScanner) Type() core.ScanType { return core.ScanTypeSecrets }

func (s *SecretsScanner) Init(cfg *core.Config) error {
	var rules []poltergeist.Rule
	var err error

	if cfg.SecretsRulesDir != "" {
		rules, err = poltergeist.LoadRulesFromDirectory(cfg.SecretsRulesDir)
	} else {
		rules, err = poltergeist.LoadDefaultRules()
	}
	if err != nil {
		return fmt.Errorf("load secrets rules: %w", err)
	}

	if cfg.SecretsRulesDir != "" {
		defaultRules, defErr := poltergeist.LoadDefaultRules()
		if defErr == nil {
			rules = append(defaultRules, rules...)
		}
	}

	s.disableRedaction = cfg.DisableRedaction

	engineName := poltergeist.SelectEngine(rules, "auto")
	var engine poltergeist.PatternEngine
	if engineName == "hyperscan" {
		engine = poltergeist.NewHyperscanEngine()
	} else {
		engine = poltergeist.NewGoRegexEngine()
	}

	if err := engine.CompileRules(rules); err != nil {
		engine.Close()
		return fmt.Errorf("compile secrets rules: %w", err)
	}

	scanner := poltergeist.NewScanner(engine)
	if cfg.Workers > 0 {
		scanner.WorkerCount = cfg.Workers
	}
	if cfg.MaxFileSize > 0 {
		scanner.MaxFileSize = cfg.MaxFileSize
	}
	scanner.DisableRedaction = cfg.DisableRedaction

	s.scanner = scanner
	return nil
}

func (s *SecretsScanner) Scan(ctx context.Context, paths []string, findings chan<- core.Finding) error {
	defer close(findings)

	for _, target := range paths {
		if ctx.Err() != nil {
			return nil
		}

		results, err := s.scanner.ScanDirectory(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: secrets scan of %s: %v\n", target, err)
			continue
		}

		for _, r := range results {
			if !r.RuleEntropyThresholdMet {
				continue
			}

			redacted := r.Redacted
			snippet := redacted
			if s.disableRedaction && r.Match != "" {
				snippet = r.Match
			}

			finding := core.Finding{
				Type:        core.ScanTypeSecrets,
				RuleID:      r.RuleID,
				RuleName:    r.RuleName,
				Severity:    core.SeverityHigh,
				Title:       "Secret detected: " + r.RuleName,
				Description: fmt.Sprintf("Potential secret found matching rule %q", r.RuleName),
				FilePath:    r.FilePath,
				StartLine:   r.LineNumber,
				EndLine:     r.LineNumber,
				Snippet:     snippet,
				Redacted:    redacted,
				Entropy:     r.Entropy,
				Tags:        []string{"secrets"},
				Timestamp:   time.Now(),
			}
			finding.ComputeFingerprint()

			select {
			case findings <- finding:
			case <-ctx.Done():
				return nil
			}
		}
	}

	return nil
}

func (s *SecretsScanner) Close() error {
	if s.scanner != nil {
		s.scanner.Engine.Close()
	}
	return nil
}

func LoadDefaultRules() ([]poltergeist.Rule, error) {
	return poltergeist.LoadDefaultRules()
}

func ValidateRules(rules []poltergeist.Rule) []error {
	var errs []error
	engine := poltergeist.NewGoRegexEngine()
	defer engine.Close()

	if err := engine.CompileRules(rules); err != nil {
		return []error{fmt.Errorf("compile rules: %w", err)}
	}

	for _, rule := range rules {
		for _, assert := range rule.Tests.Assert {
			matches := engine.FindAllInLine(assert)
			found := false
			for _, m := range matches {
				if m.RuleID == rule.ID && m.RuleEntropyThresholdMet {
					found = true
					break
				}
			}
			if !found {
				errs = append(errs, fmt.Errorf("rule %s: assert failed - pattern should match %q", rule.ID, assert))
			}
		}

		for _, assertNot := range rule.Tests.AssertNot {
			matches := engine.FindAllInLine(assertNot)
			for _, m := range matches {
				if m.RuleID == rule.ID && m.RuleEntropyThresholdMet {
					errs = append(errs, fmt.Errorf("rule %s: assert_not failed - pattern should NOT match %q", rule.ID, assertNot))
					break
				}
			}
		}
	}

	return errs
}
