package sca

import (
	"testing"
)

func TestEvaluatePackageLookups_EmptyResults(t *testing.T) {
	d := evaluatePackageLookups(nil)
	if d.Emit {
		t.Error("expected no emit for empty results")
	}
}

func TestEvaluatePackageLookups_Exists(t *testing.T) {
	results := []packageLookup{
		{Backend: "npm-public", Status: lookupExists},
	}
	d := evaluatePackageLookups(results)
	if d.Emit {
		t.Error("expected no emit when package exists")
	}
}

func TestEvaluatePackageLookups_AllMissing(t *testing.T) {
	results := []packageLookup{
		{Backend: "npm-public", Status: lookupMissing},
		{Backend: "npm-custom", Status: lookupMissing},
	}
	d := evaluatePackageLookups(results)
	if !d.Emit {
		t.Error("expected emit when all backends return missing")
	}
	if d.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", d.Confidence)
	}
	if len(d.CheckedBackends) != 2 {
		t.Errorf("expected 2 checked backends, got %d", len(d.CheckedBackends))
	}
}

func TestEvaluatePackageLookups_MixedMissingAndUncertain(t *testing.T) {
	results := []packageLookup{
		{Backend: "npm-public", Status: lookupMissing},
		{Backend: "npm-custom", Status: lookupTransientError},
	}
	d := evaluatePackageLookups(results)
	if d.Emit {
		t.Error("expected no emit when results are mixed (not all missing)")
	}
}

func TestEvaluatePackageLookups_PrivateOrUnsupported(t *testing.T) {
	results := []packageLookup{
		{Backend: "npm-public", Status: lookupPrivateOrUnsupported},
	}
	d := evaluatePackageLookups(results)
	if d.Emit {
		t.Error("expected no emit for private/unsupported package")
	}
}

func TestEvaluatePackageLookups_ExistsOverridesMissing(t *testing.T) {
	results := []packageLookup{
		{Backend: "npm-custom", Status: lookupMissing},
		{Backend: "npm-public", Status: lookupExists},
	}
	d := evaluatePackageLookups(results)
	if d.Emit {
		t.Error("expected no emit when at least one backend reports exists")
	}
}

func TestNormalizeRegistryPackageName_PyPI(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Requests", "requests"},
		{"Django", "django"},
		{"Flask-Cors", "flask-cors"},
		{"my.package", "my-package"},
		{"My__Package", "my-package"},
	}
	for _, c := range cases {
		got := normalizeRegistryPackageName("PyPI", c.input)
		if got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestNormalizeRegistryEcosystem(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"npm", "npm"},
		{"JavaScript", "npm"},
		{"PyPI", "pypi"},
		{"Python", "pypi"},
		{"crates.io", "crates"},
		{"Rust", "crates"},
		{"Go", ""},
		{"Maven", ""},
	}
	for _, c := range cases {
		got := normalizeRegistryEcosystem(c.input)
		if got != c.want {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestRegistryLookupURL(t *testing.T) {
	cases := []struct {
		eco     string
		baseURL string
		name    string
		wantOK  bool
		wantURL string
	}{
		{"npm", "https://registry.npmjs.org", "express", true, "https://registry.npmjs.org/express"},
		{"pypi", "https://pypi.org", "requests", true, "https://pypi.org/pypi/requests/json"},
		{"crates", "https://crates.io", "serde", true, "https://crates.io/api/v1/crates/serde"},
		{"go", "https://proxy.golang.org", "github.com/foo/bar", false, ""},
	}
	for _, c := range cases {
		got, ok := registryLookupURL(c.eco, c.baseURL, c.name)
		if ok != c.wantOK {
			t.Errorf("registryLookupURL(%q, %q, %q) ok=%v, want %v", c.eco, c.baseURL, c.name, ok, c.wantOK)
			continue
		}
		if ok && got != c.wantURL {
			t.Errorf("registryLookupURL(%q, %q, %q) = %q, want %q", c.eco, c.baseURL, c.name, got, c.wantURL)
		}
	}
}
