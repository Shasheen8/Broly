package triage

import (
	"regexp"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/scanignore"
)

var credentialLiteralRE = regexp.MustCompile(`["']([^"']+)["']`)

func isCredentialFinding(f *core.Finding) bool {
	if f == nil {
		return false
	}
	if f.Type == core.ScanTypeSecrets {
		return true
	}
	name := strings.ToLower(f.RuleName)
	if strings.Contains(name, "secret") ||
		strings.Contains(name, "credential") ||
		strings.Contains(name, "api key") ||
		strings.Contains(name, "password") ||
		strings.Contains(name, "token") {
		return true
	}
	id := strings.ToLower(f.RuleID)
	return strings.Contains(id, "hardcoded_secret") ||
		strings.Contains(id, "jwt_secret") ||
		strings.Contains(id, "private_key")
}

func credentialLiteralFromContext(f *core.Finding, cloneDir string) string {
	if f == nil {
		return ""
	}
	if lit := firstQuotedLiteral(f.Snippet); lit != "" {
		return lit
	}
	abs := safeAbsPath(cloneDir, f.FilePath)
	if abs == "" || f.StartLine <= 0 {
		return ""
	}
	line := core.FileContextSafe(abs, f.StartLine, f.StartLine, 0)
	return firstQuotedLiteral(line)
}

func firstQuotedLiteral(s string) string {
	m := credentialLiteralRE.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func autoTestCredentialVerdict(f *core.Finding, cloneDir string) (verdict, confidence, reason string, ok bool) {
	if !scanignore.IsTestFile(f.FilePath) || !isCredentialFinding(f) {
		return "", "", "", false
	}
	lit := credentialLiteralFromContext(f, cloneDir)
	if lit != "" && scanignore.IsObviousTestCredentialLiteral(lit) {
		return "FALSE_POSITIVE", "HIGH",
			"Test-only file with an obvious mock or placeholder credential literal.", true
	}
	return "", "", "", false
}
