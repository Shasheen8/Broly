package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/baseline"
	"github.com/Shasheen8/Broly/pkg/chain"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/sast"
	"github.com/Shasheen8/Broly/pkg/sca"
	"github.com/Shasheen8/Broly/pkg/suppress"
	"github.com/Shasheen8/Broly/pkg/triage"
	"github.com/Shasheen8/Broly/pkg/vulnclass"
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
	scannerDurations := make(map[string]time.Duration, len(o.scanners))
	var durationsMu sync.Mutex

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

			start := time.Now()
			if err := s.Scan(ctx, o.config.Targets, ch); err != nil {
				errCh <- fmt.Errorf("scanner %s: %w", s.Name(), err)
			}
			durationsMu.Lock()
			scannerDurations[s.Name()] = time.Since(start)
			durationsMu.Unlock()
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
	normalizeFindingPaths(findings, o.config.PathStripPrefix)
	sast.EnrichFindings(findings)
	findings = deduplicateFindings(findings)

	// Compute priority scores.
	for i := range findings {
		findings[i].ComputePriorityScore()
	}

	// Baseline: check required findings against full deduplicated set (before any filtering).
	// Suppression is applied after other filters.
	var (
		inlineSuppressed     int
		baselineSuppressed   int
		additionalSuppressed int
		missingRequired      []string
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
	findings = vulnclass.Filter(findings, o.config.VulnClasses)
	findings, inlineSuppressed = suppress.Filter(findings)
	if bl != nil {
		findings, baselineSuppressed = bl.Suppress(findings)
	}
	findings, additionalSuppressed = suppressByFingerprint(findings, o.config.AdditionalSuppressions)

	// Supply chain audit: check dependencies against known-malicious package
	// feeds via depx. Opt-in via --supply-chain.
	if o.config.SupplyChain && len(o.config.Targets) > 0 {
		scanRoot := o.config.Targets[0]
		scCtx, scCancel := context.WithTimeout(ctx, 5*time.Minute)
		defer scCancel()
		malicious, err := sca.AuditMaliciousPackages(scCtx, scanRoot)
		if err != nil {
			core.Warnf("supply chain audit failed: %v", err)
		} else if len(malicious) > 0 {
			for i := range malicious {
				malicious[i].ComputeIdentityKeys()
			}
			findings = append(findings, malicious...)
		}
	}

	// AI triage: verdict + fix suggestion for SAST findings.
	// Agentic triage (repo tool use) is auto-enabled for high-severity SAST
	// findings when a clone dir is available.
	var triager *triage.Triager
	if o.config.AITriage && len(findings) > 0 {
		cloneDir := o.config.PathStripPrefix
		if cloneDir == "" && len(o.config.Targets) > 0 {
			cloneDir = o.config.Targets[0]
		}
		triager = triage.New(o.config.AIModel, o.config.Explain, cloneDir)
		if triager != nil {
			findings = triager.Run(ctx, findings)
		} else {
			core.Warnf("TOGETHER_API_KEY not set - AI triage disabled")
		}
	}

	// Adversarial verification: two-stage falsification + agent verify on
	// critical SAST true positives only. Opt-in via --adversarial.
	if o.config.Adversarial && o.config.AITriage && triager != nil && len(findings) > 0 {
		advCtx, advCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer advCancel()
		findings = triager.RunAdversarial(advCtx, findings)
	}

	// Exploit chain synthesis: LLM links 2-4 cross-scanner true positives
	// into multi-step attack narratives. Opt-in via --exploit-chains.
	var exploitChains []core.ExploitChain
	if o.config.ExploitChains && o.config.AITriage && len(findings) > 0 {
		client, ok := ai.New(o.config.AIModel)
		if !ok {
			core.Warnf("TOGETHER_API_KEY not set - exploit chains disabled")
		} else {
			exploitChains, findings = chain.BuildExploitChains(ctx, client, findings)
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
		ExploitChains:   exploitChains,
		ScanTypes:       scanTypes,
		Metrics:         core.ScanMetrics{FindingsCount: len(findings), ScannerDurations: scannerDurations},
		SuppressedCount: inlineSuppressed + baselineSuppressed + additionalSuppressed,
		MissingRequired: missingRequired,
	}, nil
}

func deduplicateFindings(findings []core.Finding) []core.Finding {
	seen := make(map[string]bool, len(findings))
	out := make([]core.Finding, 0, len(findings))
	for i := range findings {
		if findings[i].Fingerprint == "" {
			findings[i].ComputeIdentityKeys()
		} else {
			findings[i].ComputeOrgMatchKey()
			findings[i].ComputeBaselineMatchKey()
			findings[i].ComputeUsageDeltaKey()
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

func normalizeFindingPaths(findings []core.Finding, prefix string) {
	if prefix == "" {
		return
	}

	prefix = strings.TrimRight(prefix, "/")
	for i := range findings {
		originalFilePath := findings[i].FilePath
		originalArtifactPath := findings[i].ArtifactPath
		findings[i].FilePath = trimPathPrefix(findings[i].FilePath, prefix)
		findings[i].ArtifactPath = trimPathPrefix(findings[i].ArtifactPath, prefix)
		if findings[i].FilePath != originalFilePath || findings[i].ArtifactPath != originalArtifactPath {
			findings[i].ComputeIdentityKeys()
		}
	}
}

func trimPathPrefix(path, prefix string) string {
	if path == "" || prefix == "" {
		return path
	}
	if !strings.HasPrefix(path, prefix) {
		return path
	}

	trimmed := strings.TrimPrefix(path, prefix)
	return strings.TrimPrefix(trimmed, "/")
}

func suppressByFingerprint(findings []core.Finding, fingerprints []string) ([]core.Finding, int) {
	suppressed := toSet(fingerprints)
	if len(suppressed) == 0 {
		return findings, 0
	}

	filtered := make([]core.Finding, 0, len(findings))
	var count int
	for _, finding := range findings {
		if !finding.BaselineSuppressible() {
			filtered = append(filtered, finding)
			continue
		}
		if finding.Fingerprint != "" && suppressed[finding.Fingerprint] {
			count++
			continue
		}
		if finding.BaselineMatchKey != "" && suppressed[finding.BaselineMatchKey] {
			count++
			continue
		}
		if finding.PackageName != "" && finding.PackageVersion != "" &&
			(finding.Type == core.ScanTypeSCA || finding.Type == core.ScanTypeContainer) {
			if key := core.PackageGroupBaselineMatchKey(finding); key != "" && suppressed[key] {
				count++
				continue
			}
		}
		filtered = append(filtered, finding)
	}
	return filtered, count
}
