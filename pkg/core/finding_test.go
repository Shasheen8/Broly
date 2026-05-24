package core

import "testing"

func TestComputeFingerprintSCADiffersByFile(t *testing.T) {
	a := Finding{
		Type:           ScanTypeSCA,
		RuleID:         "GHSA-123",
		PackageName:    "lodash",
		PackageVersion: "1.0.0",
		Ecosystem:      "npm",
		FilePath:       "/repo/app-a/package-lock.json",
	}
	b := a
	b.FilePath = "/repo/app-b/package-lock.json"

	a.ComputeFingerprint()
	b.ComputeFingerprint()

	if a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected distinct SCA fingerprints for different files")
	}
}

func TestComputeFingerprintContainerIncludesArtifactPathAndLayer(t *testing.T) {
	base := Finding{
		Type:           ScanTypeContainer,
		RuleID:         "GHSA-123",
		PackageName:    "lodash",
		PackageVersion: "1.0.0",
		Ecosystem:      "npm",
		FilePath:       "alpine:3.19",
	}

	a := base
	a.LayerDigest = "sha256:layer-a"
	a.ArtifactPath = "srv/app/package-lock.json"

	b := base
	b.LayerDigest = "sha256:layer-a"
	b.ArtifactPath = "srv/worker/package-lock.json"

	c := base
	c.LayerDigest = "sha256:layer-b"
	c.ArtifactPath = "srv/app/package-lock.json"

	a.ComputeFingerprint()
	b.ComputeFingerprint()
	c.ComputeFingerprint()

	if a.Fingerprint == b.Fingerprint {
		t.Fatalf("expected container fingerprints to differ by artifact path")
	}
	if a.Fingerprint == c.Fingerprint {
		t.Fatalf("expected container fingerprints to differ by layer")
	}
}

func TestComputeBaselineMatchKeySASTIgnoresLLMWordingAndMinorLineDrift(t *testing.T) {
	base := Finding{
		Type:        ScanTypeSAST,
		FilePath:    "internal/handler.go",
		StartLine:   10,
		RuleID:      "broly.sast.ai.sql_injection",
		RuleName:    "SQL injection in query builder",
		Description: "User input reaches a SQL sink without parameterization.",
		CWE:         []string{"CWE-89"},
	}
	shifted := base
	shifted.StartLine = 13
	shifted.RuleID = "broly.sast.ai.untrusted_sql_concat"
	shifted.RuleName = "Untrusted input concatenated into SQL"
	shifted.Description = "Unsanitized request data is interpolated into SQL."

	base.ComputeBaselineMatchKey()
	shifted.ComputeBaselineMatchKey()

	if base.BaselineMatchKey == "" {
		t.Fatal("expected non-empty SAST baseline match key")
	}
	if base.BaselineMatchKey != shifted.BaselineMatchKey {
		t.Fatalf("expected SAST baseline match key to ignore wording drift and minor line movement")
	}

	upward := base
	upward.StartLine = 5
	upward.ComputeBaselineMatchKey()
	if base.BaselineMatchKey != upward.BaselineMatchKey {
		t.Fatalf("expected SAST baseline match key to tolerate minor upward line drift")
	}
}

func TestComputeBaselineMatchKeySecretsIgnoresLineDrift(t *testing.T) {
	a := Finding{
		Type:      ScanTypeSecrets,
		RuleID:    "broly.secret.aws_access_key",
		FilePath:  "config/app.env",
		StartLine: 5,
		Redacted:  "AKIA<redacted>",
	}
	b := a
	b.StartLine = 42

	a.ComputeFingerprint()
	b.ComputeFingerprint()
	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()

	if a.Fingerprint == b.Fingerprint {
		t.Fatal("expected secrets fingerprint to remain line-sensitive")
	}
	if a.BaselineMatchKey == "" {
		t.Fatal("expected non-empty secrets baseline match key")
	}
	if a.BaselineMatchKey != b.BaselineMatchKey {
		t.Fatal("expected secrets baseline match key to survive line drift")
	}
}

func TestComputeBaselineMatchKeyContainerIgnoresLayerDigestDrift(t *testing.T) {
	a := Finding{
		Type:           ScanTypeContainer,
		RuleID:         "GHSA-123",
		PackageName:    "openssl",
		PackageVersion: "1.1.1",
		Ecosystem:      "debian",
		FilePath:       "ghcr.io/example/app:latest",
		ArtifactPath:   "usr/lib/libssl.so",
		LayerDigest:    "sha256:layer-a",
	}
	b := a
	b.LayerDigest = "sha256:layer-b"

	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()

	if a.BaselineMatchKey == "" {
		t.Fatal("expected non-empty container baseline match key")
	}
	if a.BaselineMatchKey != b.BaselineMatchKey {
		t.Fatal("expected container baseline match key to ignore layer digest drift")
	}
}

func TestComputeBaselineMatchKeySASTDistinguishesDifferentAIFindingsWithoutCWE(t *testing.T) {
	a := Finding{
		Type:        ScanTypeSAST,
		FilePath:    "internal/handler.go",
		StartLine:   12,
		RuleID:      "broly.sast.ai.untrusted_sql_concat",
		RuleName:    "Untrusted input concatenated into SQL",
		Description: "Unsanitized request data is interpolated into SQL.",
		Tags:        []string{"sast", "ai"},
	}
	b := a
	b.RuleID = "broly.sast.ai.command_injection_exec"
	b.RuleName = "User input reaches os/exec"
	b.Description = "Unsanitized input reaches process execution."

	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()

	if a.BaselineMatchKey == "" || b.BaselineMatchKey == "" {
		t.Fatal("expected non-empty SAST baseline match keys")
	}
	if a.BaselineMatchKey == b.BaselineMatchKey {
		t.Fatal("expected distinct AI SAST findings without CWE to keep separate baseline keys")
	}
}

func TestComputeBaselineMatchKeySecretsPreservesCaseSensitiveValues(t *testing.T) {
	a := Finding{
		Type:     ScanTypeSecrets,
		RuleID:   "broly.secret.generic_token",
		FilePath: "config/app.env",
		Redacted: "AbCdEf123",
	}
	b := a
	b.Redacted = "abcdef123"

	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()

	if a.BaselineMatchKey == "" || b.BaselineMatchKey == "" {
		t.Fatal("expected non-empty secrets baseline match keys")
	}
	if a.BaselineMatchKey == b.BaselineMatchKey {
		t.Fatal("expected secrets baseline keys to remain case-sensitive")
	}
}

func TestComputeUsageDeltaKeySCAIgnoresManifestPath(t *testing.T) {
	a := Finding{
		Type:           ScanTypeSCA,
		RuleID:         "GHSA-123",
		PackageName:    "lodash",
		PackageVersion: "1.0.0",
		Ecosystem:      "npm",
		FilePath:       "services/api/package-lock.json",
	}
	b := a
	b.FilePath = "services/worker/package-lock.json"

	a.ComputeBaselineMatchKey()
	b.ComputeBaselineMatchKey()
	a.ComputeUsageDeltaKey()
	b.ComputeUsageDeltaKey()

	if a.BaselineMatchKey == b.BaselineMatchKey {
		t.Fatal("expected SCA baseline match key to keep manifest-level inventory distinct")
	}
	if a.UsageDeltaKey == "" {
		t.Fatal("expected non-empty SCA usage delta key")
	}
	if a.UsageDeltaKey != b.UsageDeltaKey {
		t.Fatal("expected SCA usage delta key to be repo-wide rather than manifest-specific")
	}
}

func TestComputeIdentityKeysPopulatesSCAIdentityFamily(t *testing.T) {
	f := Finding{
		Type:           ScanTypeSCA,
		RuleID:         "GHSA-123",
		PackageName:    "lodash",
		PackageVersion: "1.0.0",
		Ecosystem:      "npm",
		FilePath:       "services/api/package-lock.json",
	}

	f.ComputeIdentityKeys()

	if f.Fingerprint == "" {
		t.Fatal("expected fingerprint to be populated")
	}
	if f.OrgMatchKey == "" {
		t.Fatal("expected org match key to be populated")
	}
	if f.BaselineMatchKey == "" {
		t.Fatal("expected baseline match key to be populated")
	}
	if f.UsageDeltaKey == "" {
		t.Fatal("expected usage delta key to be populated")
	}
}
