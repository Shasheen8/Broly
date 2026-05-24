package sca

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"

	"github.com/Shasheen8/Broly/pkg/core"
)

type lookupStatus string

const (
	lookupExists               lookupStatus = "exists"
	lookupMissing              lookupStatus = "missing"
	lookupPrivateOrUnsupported lookupStatus = "private_or_unsupported"
	lookupTransientError       lookupStatus = "transient_error"
	lookupAmbiguous            lookupStatus = "ambiguous"
)

type packageCandidate struct {
	Name      string
	Version   string
	Ecosystem string
	FilePath  string
}

type packageLookup struct {
	Backend        string
	Status         lookupStatus
	NormalizedName string
	Reason         string
}

type packageIntelligence struct {
	backends []registryBackend
}

func newPackageIntelligence(cfg *core.Config) (*packageIntelligence, error) {
	backends, err := buildRegistryBackends(cfg)
	if err != nil {
		return nil, err
	}
	if len(backends) == 0 {
		return nil, nil
	}
	return &packageIntelligence{backends: backends}, nil
}

func (p *packageIntelligence) Analyze(ctx context.Context, pkgs []*extractor.Package) []core.Finding {
	if p == nil || len(p.backends) == 0 {
		return nil
	}

	findings := make([]core.Finding, 0)
	lookupCache := make(map[string]packageLookup)
	emitted := make(map[string]bool)

	for _, pkg := range pkgs {
		candidate := newPackageCandidate(pkg)
		results := p.lookupPackage(ctx, candidate, lookupCache)
		decision := evaluatePackageLookups(results)
		if !decision.Emit {
			continue
		}

		finding := core.Finding{
			Type:           core.ScanTypeSCA,
			RuleID:         hallucinatedPackageRuleID,
			RuleName:       "Package intelligence: missing package",
			Severity:       core.SeverityMedium,
			Confidence:     decision.Confidence,
			Title:          fmt.Sprintf("Package not found in configured registries: %s@%s", candidate.Name, candidate.Version),
			Description:    fmt.Sprintf("Package %s@%s was extracted from project manifests but was missing from all configured %s backends (%s).", candidate.Name, candidate.Version, candidate.Ecosystem, strings.Join(decision.CheckedBackends, ", ")),
			FilePath:       candidate.FilePath,
			StartLine:      1,
			EndLine:        1,
			PackageName:    candidate.Name,
			PackageVersion: candidate.Version,
			Ecosystem:      candidate.Ecosystem,
			Tags:           []string{"sca", "package-intelligence", "hallucinated-package", registryTag(candidate.Ecosystem)},
			Timestamp:      time.Now(),
		}
		finding.ComputeFingerprint()
		if emitted[finding.Fingerprint] {
			continue
		}
		emitted[finding.Fingerprint] = true
		findings = append(findings, finding)
	}

	return findings
}

func newPackageCandidate(pkg *extractor.Package) packageCandidate {
	location := ""
	if len(pkg.Locations) > 0 {
		location = pkg.Locations[0]
	}
	return packageCandidate{
		Name:      pkg.Name,
		Version:   pkg.Version,
		Ecosystem: pkg.Ecosystem().String(),
		FilePath:  location,
	}
}

func (p *packageIntelligence) lookupPackage(ctx context.Context, pkg packageCandidate, cache map[string]packageLookup) []packageLookup {
	results := make([]packageLookup, 0, len(p.backends))
	for _, backend := range p.backends {
		if !backend.Supports(pkg) {
			continue
		}
		normalizedName := normalizeRegistryPackageName(pkg.Ecosystem, pkg.Name)
		cacheKey := strings.Join([]string{backend.Name(), normalizeRegistryEcosystem(pkg.Ecosystem), normalizedName}, ":")
		result, ok := cache[cacheKey]
		if !ok {
			result = backend.Lookup(ctx, pkg)
			if result.Backend == "" {
				result.Backend = backend.Name()
			}
			cache[cacheKey] = result
		}
		results = append(results, result)
	}
	return results
}

type packageDecision struct {
	Emit            bool
	Confidence      string
	CheckedBackends []string
}

func evaluatePackageLookups(results []packageLookup) packageDecision {
	if len(results) == 0 {
		return packageDecision{}
	}

	checked := make([]string, 0, len(results))
	seen := make(map[string]bool)
	onlyMissing := true

	for _, result := range results {
		if result.Backend != "" && !seen[result.Backend] {
			seen[result.Backend] = true
			checked = append(checked, result.Backend)
		}
		switch result.Status {
		case lookupExists:
			return packageDecision{CheckedBackends: checked}
		case lookupMissing:
		case lookupPrivateOrUnsupported, lookupTransientError, lookupAmbiguous:
			onlyMissing = false
		default:
			onlyMissing = false
		}
	}

	if !onlyMissing {
		return packageDecision{CheckedBackends: checked}
	}

	return packageDecision{
		Emit:            true,
		Confidence:      "high",
		CheckedBackends: checked,
	}
}
