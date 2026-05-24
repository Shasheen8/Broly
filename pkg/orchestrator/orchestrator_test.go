package orchestrator

import (
	"testing"

	"github.com/Shasheen8/Broly/pkg/core"
)

func TestNormalizeFindingPathsRecomputesIdentityKeys(t *testing.T) {
	findings := []core.Finding{{
		Type:           core.ScanTypeSCA,
		RuleID:         "GHSA-123",
		PackageName:    "lodash",
		PackageVersion: "1.0.0",
		Ecosystem:      "npm",
		FilePath:       "/repo/services/api/package-lock.json",
	}}

	findings[0].ComputeFingerprint()
	findings[0].ComputeBaselineMatchKey()
	findings[0].ComputeUsageDeltaKey()

	beforeFingerprint := findings[0].Fingerprint
	beforeBaseline := findings[0].BaselineMatchKey
	beforeUsage := findings[0].UsageDeltaKey

	normalizeFindingPaths(findings, "/repo")

	if findings[0].FilePath != "services/api/package-lock.json" {
		t.Fatalf("normalizeFindingPaths file path = %q", findings[0].FilePath)
	}
	if findings[0].Fingerprint == beforeFingerprint {
		t.Fatal("expected fingerprint to change after path normalization")
	}
	if findings[0].BaselineMatchKey == beforeBaseline {
		t.Fatal("expected baseline match key to change after path normalization")
	}
	if findings[0].UsageDeltaKey != beforeUsage {
		t.Fatal("expected usage delta key to stay repo-wide after path normalization")
	}
}
