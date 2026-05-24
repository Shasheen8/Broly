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
