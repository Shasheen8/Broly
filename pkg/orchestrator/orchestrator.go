package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/Shasheen8/Broly/pkg/baseline"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/suppress"
	"github.com/Shasheen8/Broly/pkg/triage"
)

type Orchestrator struct {
	scanners []core.Scanner
	config   *core.Config
}

func New(cfg *core.Config) *Orchestrator {
	return &Orchestrator{config: cfg}
}

func (o *Orchestrator) Register(s core.Scanner) {
	o.scanners = append(o.scanners, s)
}

func (o *Orchestrator) Run(ctx context.Context) (*core.ScanResult, error) {
	for _, s := range o.scanners {
		if err := s.Init(o.config); err != nil {
			return nil, fmt.Errorf("init scanner %s: %w", s.Name(), err)
		}
	}
	defer func() {
		for _, s := range o.scanners {
			s.Close()
		}
	}()

	aggregated := make(chan core.Finding, 256)
	findings := make([]core.Finding, 0, 256)

	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for f := range aggregated {
			findings = append(findings, f)
		}
	}()

	var scanWg sync.WaitGroup
	var fwdWg sync.WaitGroup
	errCh := make(chan error, len(o.scanners))

	for _, scanner := range o.scanners {
		scanWg.Add(1)
		fwdWg.Add(1)
		go func(s core.Scanner) {
			defer scanWg.Done()

			ch := make(chan core.Finding, 64)
			go func() {
				defer fwdWg.Done()
				for f := range ch {
					select {
					case aggregated <- f:
					case <-ctx.Done():
						for range ch {
						} // drain so scanner can exit
						return
					}
				}
			}()

			if err := s.Scan(ctx, o.config.Targets, ch); err != nil {
				errCh <- fmt.Errorf("scanner %s: %w", s.Name(), err)
			}
		}(scanner)
	}

	scanWg.Wait()
	fwdWg.Wait()
	close(aggregated)
	collectWg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("scan errors: %w", errors.Join(errs...))
	}

	// Post-processing pipeline.
	findings = deduplicateFindings(findings)

	// Compute priority scores.
	for i := range findings {
		findings[i].ComputePriorityScore()
	}

	// Baseline: check required findings against full deduplicated set (before any filtering).
	// Suppression is applied after other filters.
	var (
		inlineSuppressed   int
		baselineSuppressed int
		missingRequired    []string
	)
	var bl *baseline.Baseline
	if o.config.BaselineFile != "" {
		var err error
		bl, err = baseline.Load(o.config.BaselineFile)
		if err != nil {
			core.Warnf("could not load baseline %s: %v", o.config.BaselineFile, err)
			bl = nil
		}
	}
	if bl != nil {
		missingRequired = bl.CheckRequired(findings)
	}

	// These always run regardless of baseline load success/failure.
	findings = filterBySeverity(findings, o.config.MinSeverity)
	findings = filterByRuleIDs(findings, o.config.IncludeRuleIDs, o.config.ExcludeRuleIDs)
	findings, inlineSuppressed = suppress.Filter(findings)
	if bl != nil {
		findings, baselineSuppressed = bl.Suppress(findings)
	}

	// AI triage: verdict + fix suggestion per finding.
	if o.config.AITriage && len(findings) > 0 {
		t := triage.New(o.config.AIModel, o.config.Explain)
		if t != nil {
			findings = t.Run(ctx, findings)
		} else {
			core.Warnf("TOGETHER_API_KEY not set - AI triage disabled")
		}
	}

	scanTypes := make([]core.ScanType, 0, len(o.scanners))
	typeSet := make(map[core.ScanType]bool)
	for _, s := range o.scanners {
		if !typeSet[s.Type()] {
			scanTypes = append(scanTypes, s.Type())
			typeSet[s.Type()] = true
		}
	}

	return &core.ScanResult{
		Findings:        findings,
		ScanTypes:       scanTypes,
		Metrics:         core.ScanMetrics{FindingsCount: len(findings)},
		SuppressedCount: inlineSuppressed + baselineSuppressed,
		MissingRequired: missingRequired,
	}, nil
}

func deduplicateFindings(findings []core.Finding) []core.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]core.Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].ComputeFingerprint()
		}
		if !seen[findings[i].Fingerprint] {
			seen[findings[i].Fingerprint] = true
			out = append(out, findings[i])
		}
	}
	return out
}

func filterBySeverity(findings []core.Finding, min core.Severity) []core.Finding {
	if min == core.SeverityInfo {
		return findings
	}
	filtered := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= min {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func filterByRuleIDs(findings []core.Finding, include, exclude []string) []core.Finding {
	if len(include) == 0 && len(exclude) == 0 {
		return findings
	}
	includeSet := toSet(include)
	excludeSet := toSet(exclude)
	filtered := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		if len(includeSet) > 0 && !includeSet[f.RuleID] {
			continue
		}
		if excludeSet[f.RuleID] {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func toSet(items []string) map[string]bool {
	if len(items) == 0 {
		return nil
	}
	s := make(map[string]bool, len(items))
	for _, item := range items {
		s[item] = true
	}
	return s
}
