package sast

import (
	"strconv"
	"strings"

	"github.com/Shasheen8/Broly/pkg/core"
)

// parseLLMResponse parses the LLM's structured markdown output into findings.
func parseLLMResponse(filePath, response string) []parsedFinding {
	resp := strings.TrimSpace(response)
	if resp == "" || strings.Contains(resp, "NO_FINDINGS") {
		return nil
	}

	var findings []parsedFinding
	var current *parsedFinding
	inFix := false

	lines := strings.Split(resp, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)

		if _, val, ok := extractField(line, "Vulnerability Level"); ok {
			if current != nil {
				findings = append(findings, *current)
			}
			current = &parsedFinding{}
			current.level = strings.Trim(val, "[]")
			inFix = false
			continue
		}

		if current == nil {
			continue
		}

		if _, val, ok := extractField(line, "Issue"); ok {
			current.issue = val
			inFix = false
		} else if _, val, ok := extractField(line, "Location"); ok {
			current.location = val
			inFix = false
		} else if _, val, ok := extractField(line, "Risk"); ok {
			current.risk = val
			inFix = false
		} else if _, val, ok := extractField(line, "Fix"); ok {
			current.fix = val
			inFix = true
		} else if line == "---" || line == "***" {
			inFix = false
		} else if line != "" && inFix {
			if current.fix != "" {
				current.fix += "\n" + line
			} else {
				current.fix = line
			}
		}
	}

	if current != nil {
		findings = append(findings, *current)
	}

	return findings
}

type parsedFinding struct {
	level    string
	issue    string
	location string
	risk     string
	fix      string
}

func extractField(line, field string) (string, string, bool) {
	prefix1 := "- **" + field + "**:"
	prefix2 := "**" + field + "**:"

	var rest string
	if strings.HasPrefix(line, prefix1) {
		rest = strings.TrimPrefix(line, prefix1)
	} else if strings.HasPrefix(line, prefix2) {
		rest = strings.TrimPrefix(line, prefix2)
	} else {
		return "", "", false
	}

	return field, strings.TrimSpace(rest), true
}

func (p *parsedFinding) toFinding(filePath, lang string) core.Finding {
	sev := parseLLMSeverity(p.level)

	scanType, rulePrefix, tags := scanTypeForLang(lang)
	ruleID := rulePrefix + slugify(p.issue)

	startLine := extractLineNumber(p.location)
	description := p.risk
	if description == "" {
		description = p.issue
	}

	fix := p.fix
	cwe := extractCWE(p.issue + " " + p.risk)

	f := core.Finding{
		Type:          scanType,
		RuleID:        ruleID,
		RuleName:      p.issue,
		Severity:      sev,
		Confidence:    "high",
		Title:         p.issue,
		Description:   description,
		FilePath:      filePath,
		StartLine:     startLine,
		CWE:           cwe,
		Tags:          tags,
		FixSuggestion: fix,
	}

	f.ComputeFingerprint()
	return f
}

func scanTypeForLang(lang string) (core.ScanType, string, []string) {
	switch lang {
	case "dockerfile", "docker-compose":
		return core.ScanTypeDockerfile, "broly.dockerfile.", []string{"dockerfile", "ai"}
	default:
		return core.ScanTypeSAST, "broly.sast.ai.", []string{"sast", "ai"}
	}
}

func parseLLMSeverity(level string) core.Severity {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "CRITICAL":
		return core.SeverityCritical
	case "HIGH":
		return core.SeverityHigh
	case "MEDIUM":
		return core.SeverityMedium
	case "LOW":
		return core.SeverityLow
	default:
		return core.SeverityInfo
	}
}

func extractLineNumber(loc string) int {
	if loc == "" || loc == "N/A" {
		return 0
	}
	// Try "file:linenum" or "file:linenum-linenum"
	if idx := strings.LastIndex(loc, ":"); idx >= 0 {
		part := loc[idx+1:]
		if dash := strings.Index(part, "-"); dash >= 0 {
			part = part[:dash]
		}
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n > 0 {
			return n
		}
	}
	// Try "line N"
	lower := strings.ToLower(loc)
	if idx := strings.Index(lower, "line "); idx >= 0 {
		part := strings.TrimSpace(loc[idx+5:])
		if n, err := strconv.Atoi(part); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

func slugify(s string) string {
	var b strings.Builder
	lastUnderscore := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if b.Len() > 0 && !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	result := strings.Trim(b.String(), "_")
	if len(result) > 50 {
		result = result[:50]
	}
	if result == "" {
		return "unknown"
	}
	return result
}

func extractCWE(text string) []string {
	var cwes []string
	seen := make(map[string]bool)
	upper := strings.ToUpper(text)
	idx := 0
	for {
		pos := strings.Index(upper[idx:], "CWE-")
		if pos < 0 {
			break
		}
		abs := idx + pos
		end := abs + 4
		for end < len(upper) && upper[end] >= '0' && upper[end] <= '9' {
			end++
		}
		if end > abs+4 {
			cwe := upper[abs:end]
			if !seen[cwe] {
				seen[cwe] = true
				cwes = append(cwes, cwe)
			}
		}
		idx = abs + 4
	}
	return cwes
}
