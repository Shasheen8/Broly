package sca

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var registryHTTPClient = &http.Client{Timeout: 5 * time.Second}

const hallucinatedPackageRuleID = "broly.sca.hallucinated-package"

var pypiNameNormalizer = regexp.MustCompile(`[-_.]+`)

type registryBackend interface {
	Name() string
	Supports(pkg packageCandidate) bool
	Lookup(ctx context.Context, pkg packageCandidate) packageLookup
}

type httpRegistryBackend struct {
	name      string
	ecosystem string
	baseURL   string
	client    *http.Client
}

func newHTTPRegistryBackend(name, ecosystem, baseURL string) registryBackend {
	return httpRegistryBackend{
		name:      name,
		ecosystem: ecosystem,
		baseURL:   strings.TrimRight(baseURL, "/"),
		client:    registryHTTPClient,
	}
}

func (b httpRegistryBackend) Name() string { return b.name }

func (b httpRegistryBackend) Supports(pkg packageCandidate) bool {
	return normalizeRegistryEcosystem(pkg.Ecosystem) == b.ecosystem
}

func (b httpRegistryBackend) Lookup(ctx context.Context, pkg packageCandidate) packageLookup {
	normalized := normalizeRegistryPackageName(b.ecosystem, pkg.Name)
	result := packageLookup{
		Backend:        b.name,
		NormalizedName: normalized,
	}

	if normalized == "" {
		result.Status = lookupAmbiguous
		result.Reason = "empty normalized package name"
		return result
	}
	lookupURL, ok := registryLookupURL(b.ecosystem, b.baseURL, normalized)
	if !ok {
		result.Status = lookupPrivateOrUnsupported
		result.Reason = "unsupported ecosystem"
		return result
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		result.Status = lookupTransientError
		result.Reason = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "broly-sca/1.0")

	resp, err := b.client.Do(req)
	if err != nil {
		result.Status = lookupTransientError
		result.Reason = err.Error()
		return result
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		result.Status = lookupExists
	case http.StatusNotFound:
		result.Status = lookupMissing
	case http.StatusUnauthorized, http.StatusForbidden:
		result.Status = lookupAmbiguous
		result.Reason = fmt.Sprintf("registry returned status %d", resp.StatusCode)
	case http.StatusTooManyRequests:
		result.Status = lookupTransientError
		result.Reason = "registry rate limited"
	default:
		if resp.StatusCode >= 500 {
			result.Status = lookupTransientError
		} else {
			result.Status = lookupAmbiguous
		}
		result.Reason = fmt.Sprintf("registry returned status %d", resp.StatusCode)
	}

	return result
}

func registryLookupURL(ecosystem, baseURL, name string) (string, bool) {
	switch normalizeRegistryEcosystem(ecosystem) {
	case "npm":
		return baseURL + "/" + url.PathEscape(name), true
	case "pypi":
		return baseURL + "/pypi/" + url.PathEscape(name) + "/json", true
	case "crates":
		return baseURL + "/api/v1/crates/" + url.PathEscape(name), true
	default:
		return "", false
	}
}

func registryTag(ecosystem string) string {
	switch normalizeRegistryEcosystem(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "crates":
		return "crates"
	default:
		return strings.ToLower(ecosystem)
	}
}

func normalizeRegistryPackageName(ecosystem, name string) string {
	switch normalizeRegistryEcosystem(ecosystem) {
	case "pypi":
		return pypiNameNormalizer.ReplaceAllString(strings.ToLower(name), "-")
	default:
		return name
	}
}

func normalizeRegistryEcosystem(ecosystem string) string {
	lower := strings.ToLower(ecosystem)
	switch {
	case strings.Contains(lower, "npm"), strings.Contains(lower, "javascript"), strings.Contains(lower, "node"):
		return "npm"
	case strings.Contains(lower, "pypi"), strings.Contains(lower, "python"):
		return "pypi"
	case strings.Contains(lower, "cargo"), strings.Contains(lower, "rust"), strings.Contains(lower, "crates"):
		return "crates"
	default:
		return ""
	}
}
