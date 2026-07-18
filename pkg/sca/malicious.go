package sca

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	ruleMaliciousKnownBad  = "sca.malicious.known_bad_package"
	ruleMaliciousTyposquat = "sca.malicious.typosquat"
)

type depxEnvelope struct {
	Command string        `json:"command"`
	Data    depxAuditData `json:"data"`
}

type depxAuditData struct {
	Findings []depxFinding `json:"findings"`
	// depx emits an error envelope (command:"error") when it can't load its
	// malicious-package index — e.g. a cold cache that can't reach
	// github.projectdiscovery.io. Without these fields the error parses as
	// zero findings and looks identical to a clean supply chain.
	Error   bool   `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type depxFinding struct {
	Verdict     string   `json:"verdict"`
	Ecosystem   string   `json:"ecosystem"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	IDs         []string `json:"ids"`
	Summary     string   `json:"summary"`
	Lockfile    string   `json:"lockfile"`
	RegistryURL string   `json:"registry_url"`
}

func AuditMaliciousPackages(ctx context.Context, scanRoot string) ([]core.Finding, error) {
	return auditMaliciousPackages(ctx, scanRoot)
}

func auditMaliciousPackages(ctx context.Context, scanRoot string) ([]core.Finding, error) {
	scanRoot = strings.TrimSpace(scanRoot)
	if scanRoot == "" {
		return nil, fmt.Errorf("empty malicious-package scan root")
	}
	scanRoot = filepath.Clean(scanRoot)
	st, err := os.Stat(scanRoot)
	if err != nil {
		return nil, fmt.Errorf("malicious-package scan root %q: %w", scanRoot, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("malicious-package scan root %q is not a directory", scanRoot)
	}
	if !DepxAvailable() {
		return nil, fmt.Errorf("depx not found: install depx or rebuild broly-app image")
	}

	cmd := exec.CommandContext(ctx, resolveDepxExecutable(), "audit", "--json", "--silent", scanRoot)
	// depx reads its malicious-package index from $HOME/.cache/depx (it ignores
	// XDG_CACHE_HOME). DEPX_HOME points depx at the image's pre-warmed/baked
	// cache without changing the broly process's own HOME (git, AWS SDK, etc.).
	if home := strings.TrimSpace(os.Getenv("DEPX_HOME")); home != "" {
		cmd.Env = append(os.Environ(), "HOME="+home)
	}
	// Capture stderr so a depx failure (missing binary, runtime error) shows up
	// in logs instead of silently producing zero malicious findings.
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return nil, fmt.Errorf("depx not found at %q", resolveDepxExecutable())
		}
		return nil, fmt.Errorf("run depx audit (stderr: %s): %w", strings.TrimSpace(stderr.String()), err)
	}

	findings, parseErr := parseDepxAuditJSON(out, scanRoot)
	if parseErr != nil {
		return nil, fmt.Errorf("%w (depx stderr: %s)", parseErr, strings.TrimSpace(stderr.String()))
	}
	if err != nil && len(findings) == 0 {
		return nil, fmt.Errorf("run depx audit (stderr: %s): %w", strings.TrimSpace(stderr.String()), err)
	}
	return findings, nil
}

func parseDepxAuditJSON(data []byte, scanRoot string) ([]core.Finding, error) {
	var env depxEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("decode depx audit json: %w", err)
	}
	if env.Data.Error || strings.EqualFold(strings.TrimSpace(env.Command), "error") {
		msg := strings.TrimSpace(env.Data.Message)
		if msg == "" {
			msg = "unknown depx error"
		}
		return nil, fmt.Errorf("depx audit error (code %d): %s", env.Data.Code, msg)
	}

	out := make([]core.Finding, 0, len(env.Data.Findings))
	emitted := make(map[string]bool)
	for _, df := range env.Data.Findings {
		if !strings.EqualFold(strings.TrimSpace(df.Verdict), "malicious") {
			continue
		}
		f, ok := depxFindingToCore(df, scanRoot)
		if !ok {
			continue
		}
		if emitted[f.Fingerprint] {
			continue
		}
		emitted[f.Fingerprint] = true
		out = append(out, f)
	}
	return out, nil
}

func depxFindingToCore(df depxFinding, scanRoot string) (core.Finding, bool) {
	name := strings.TrimSpace(df.Name)
	if name == "" {
		return core.Finding{}, false
	}
	eco := strings.TrimSpace(df.Ecosystem)
	version := strings.TrimSpace(df.Version)
	summary := strings.TrimSpace(df.Summary)
	if summary == "" {
		summary = fmt.Sprintf("Known malicious package: %s@%s", name, version)
	}

	filePath := strings.TrimSpace(df.Lockfile)
	if filePath == "" {
		filePath = scanRoot
	}
	if rel, err := filepath.Rel(scanRoot, filePath); err == nil && rel != "" && !strings.HasPrefix(rel, "..") {
		filePath = filepath.ToSlash(rel)
	} else if base := filepath.Base(filePath); base != "" && base != "." {
		filePath = filepath.ToSlash(base)
	}

	ruleID := maliciousRuleID(summary)
	advisoryID := firstAdvisoryID(df.IDs)
	title := fmt.Sprintf("Malicious package: %s@%s", name, version)
	if version == "" {
		title = fmt.Sprintf("Malicious package: %s", name)
	}

	var refs []string
	if df.RegistryURL != "" {
		refs = append(refs, df.RegistryURL)
	}
	if advisoryID != "" && strings.HasPrefix(advisoryID, "MAL-") {
		refs = append(refs, openSSFAdvisoryURL(eco, advisoryID))
	}

	finding := core.Finding{
		Type:           core.ScanTypeSCA,
		RuleID:         ruleID,
		RuleName:       ruleID,
		Severity:       core.SeverityCritical,
		Confidence:     "high",
		Title:          title,
		Description:    summary,
		FilePath:       filePath,
		StartLine:      1,
		EndLine:        1,
		PackageName:    name,
		PackageVersion: version,
		Ecosystem:      eco,
		CVE:            advisoryID,
		References:     refs,
		Tags:           []string{"sca", "malicious-package", strings.ToLower(eco)},
		Timestamp:      time.Now(),
	}
	finding.ComputeIdentityKeys()
	return finding, true
}

func maliciousRuleID(summary string) string {
	lower := strings.ToLower(summary)
	if strings.Contains(lower, "typosquat") || strings.Contains(lower, "typo") {
		return ruleMaliciousTyposquat
	}
	return ruleMaliciousKnownBad
}

func firstAdvisoryID(ids []string) string {
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			return id
		}
	}
	return ""
}

func openSSFAdvisoryURL(ecosystem, id string) string {
	ecosystem = strings.TrimSpace(strings.ToLower(ecosystem))
	id = strings.TrimSpace(id)
	if ecosystem == "" || id == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/ossf/malicious-packages/blob/main/osv/%s/%s.json", ecosystem, id)
}

func maliciousPackageLookupKey(ecosystem, name, version string) string {
	eco := normalizeRegistryEcosystem(ecosystem)
	if eco == "" {
		eco = strings.ToLower(strings.TrimSpace(ecosystem))
	}
	return eco + "\x00" + strings.TrimSpace(name) + "\x00" + strings.TrimSpace(version)
}

func maliciousPackageLookupKeyFromFinding(f core.Finding) string {
	return maliciousPackageLookupKey(f.Ecosystem, f.PackageName, f.PackageVersion)
}

func isOSVMaliciousID(id string) bool {
	id = strings.TrimSpace(id)
	return strings.HasPrefix(id, "MAL-") || strings.HasPrefix(id, "GHSCAN-MAL")
}
