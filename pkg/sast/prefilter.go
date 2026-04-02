package sast

import (
	"regexp"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

// pattern represents a regex-based vulnerability detector.
type pattern struct {
	Name     string
	CWE      string
	Severity core.Severity
	Regex    *regexp.Regexp
	Category string
}

// prefilterPatterns are deterministic regex checks that run alongside the LLM.
// Sourced from sec-context anti-patterns research (150+ security sources).
var prefilterPatterns = []pattern{
	// Secrets
	{Name: "Hardcoded secret", CWE: "CWE-798", Severity: core.SeverityCritical, Category: "secrets",
		Regex: regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token|credential)\s*[=:]\s*["'][^"']{8,}["']`)},
	{Name: "AWS access key", CWE: "CWE-798", Severity: core.SeverityCritical, Category: "secrets",
		Regex: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "Private key block", CWE: "CWE-321", Severity: core.SeverityCritical, Category: "secrets",
		Regex: regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{Name: "JWT secret", CWE: "CWE-798", Severity: core.SeverityHigh, Category: "secrets",
		Regex: regexp.MustCompile(`(?i)jwt[_-]?secret\s*[=:]\s*["'][^"']+["']`)},

	// SQL Injection
	{Name: "SQL string concatenation", CWE: "CWE-89", Severity: core.SeverityCritical, Category: "injection",
		Regex: regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*["']\s*\+\s*`)},
	{Name: "SQL f-string/format", CWE: "CWE-89", Severity: core.SeverityCritical, Category: "injection",
		Regex: regexp.MustCompile(`(?i)f["'](SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*\{`)},

	// Command Injection
	{Name: "Shell command with concat", CWE: "CWE-78", Severity: core.SeverityCritical, Category: "injection",
		Regex: regexp.MustCompile(`(?i)(os\.system|subprocess\.call|exec\.Command|child_process\.exec)\s*\(.*\+`)},
	{Name: "Shell=True", CWE: "CWE-78", Severity: core.SeverityHigh, Category: "injection",
		Regex: regexp.MustCompile(`shell\s*=\s*True`)},

	// XSS
	{Name: "innerHTML assignment", CWE: "CWE-79", Severity: core.SeverityHigh, Category: "xss",
		Regex: regexp.MustCompile(`\.innerHTML\s*=`)},
	{Name: "document.write", CWE: "CWE-79", Severity: core.SeverityHigh, Category: "xss",
		Regex: regexp.MustCompile(`document\.write\s*\(`)},

	// Crypto
	{Name: "Weak hash (MD5)", CWE: "CWE-328", Severity: core.SeverityHigh, Category: "crypto",
		Regex: regexp.MustCompile(`(?i)(md5|MD5)\s*[.(]`)},
	{Name: "Weak hash (SHA1)", CWE: "CWE-328", Severity: core.SeverityMedium, Category: "crypto",
		Regex: regexp.MustCompile(`(?i)(sha1|SHA1)\s*[.(]`)},
	{Name: "ECB mode", CWE: "CWE-327", Severity: core.SeverityHigh, Category: "crypto",
		Regex: regexp.MustCompile(`(?i)(ECB|MODE_ECB|AES\.ECB)`)},
	{Name: "Math.random for security", CWE: "CWE-330", Severity: core.SeverityHigh, Category: "crypto",
		Regex: regexp.MustCompile(`Math\.random\s*\(`)},

	// Path Traversal
	{Name: "Path concatenation", CWE: "CWE-22", Severity: core.SeverityHigh, Category: "input",
		Regex: regexp.MustCompile(`(?i)(open|read_?file|write_?file)\s*\(.*\+`)},

	// Debug/Config
	{Name: "Debug mode enabled", CWE: "CWE-215", Severity: core.SeverityMedium, Category: "config",
		Regex: regexp.MustCompile(`(?i)(DEBUG|debug)\s*[=:]\s*(true|True|1|"true")`)},
	{Name: "CORS allow all", CWE: "CWE-346", Severity: core.SeverityMedium, Category: "config",
		Regex: regexp.MustCompile(`(?i)(Access-Control-Allow-Origin|allowedOrigins?)\s*[=:]\s*["']\*["']`)},
}

// prefilterHit records where a pattern matched in a file.
type prefilterHit struct {
	Pattern pattern
	Line    int
}

// runPrefilter scans file contents for known vulnerability patterns.
func runPrefilter(content string) []prefilterHit {
	lines := strings.Split(content, "\n")
	var hits []prefilterHit

	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, p := range prefilterPatterns {
			if p.Regex.MatchString(line) {
				hits = append(hits, prefilterHit{
					Pattern: p,
					Line:    lineNum + 1,
				})
			}
		}
	}
	return hits
}
