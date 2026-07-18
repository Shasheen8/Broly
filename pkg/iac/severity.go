package iac

import (
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

// resolveCheckovSeverity prefers Checkov/Prisma severity when present, then the
// static check-ID map (Security Hub / CIS-aligned), then name heuristics so
// newly added critical checks do not silently fall through to MEDIUM.
func resolveCheckovSeverity(checkID, checkovSeverity, checkName string) core.Severity {
	if sev, ok := parseCheckovSeverity(checkovSeverity); ok {
		return sev
	}
	id := strings.TrimSpace(checkID)
	if sev, ok := severityByCheckID[id]; ok {
		return sev
	}
	if sev, ok := severityFromCheckName(checkName); ok {
		return sev
	}
	return core.SeverityMedium
}

func parseCheckovSeverity(severity string) (core.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return core.SeverityCritical, true
	case "HIGH", "IMPORTANT":
		return core.SeverityHigh, true
	case "MEDIUM", "MODERATE":
		return core.SeverityMedium, true
	case "LOW", "INFO":
		return core.SeverityLow, true
	default:
		return 0, false
	}
}

// mapCheckovSeverity maps an explicit Checkov severity string. Empty/unknown
// values return MEDIUM for backward compatibility with callers that only have
// the severity field.
func mapCheckovSeverity(severity string) core.Severity {
	if sev, ok := parseCheckovSeverity(severity); ok {
		return sev
	}
	return core.SeverityMedium
}

func severityFromCheckName(name string) (core.Severity, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return 0, false
	}
	criticalHints := []string{
		"public", "everyone", "anonymously", "0.0.0.0", "::/0", "unrestricted",
		"hard coded", "hard-coded", "hardcoded", "clear text", "clear-text", "plaintext",
		"privileged", "privilege escalation", "allowprivilegeescalation",
		"host network", "host process", "host ipc", "hostpid", "hostipc", "hostnetwork",
		"docker.sock", "docker daemon socket", "pods/exec", "nodes/proxy", "impersonate",
		"read all secrets", "root user", "administrative privileges", "any principal",
	}
	for _, h := range criticalHints {
		if strings.Contains(n, h) {
			return core.SeverityCritical, true
		}
	}
	highHints := []string{
		"encrypt", "kms", "ssl", "tls", "https", "secure transport", "mfa",
		"imdsv2", "wildcard", "runasnonroot", "readonlyrootfilesystem",
		"password policy", "key rotation", "least privilege",
	}
	for _, h := range highHints {
		if strings.Contains(n, h) {
			return core.SeverityHigh, true
		}
	}
	lowHints := []string{
		"logging", "versioning", "backup", "retention", "description",
		"tagging", "multi-az", "deletion protection",
	}
	for _, h := range lowHints {
		if strings.Contains(n, h) {
			return core.SeverityLow, true
		}
	}
	return 0, false
}
