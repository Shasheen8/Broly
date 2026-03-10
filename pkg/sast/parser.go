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

	lines := strings.Split(resp, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)

		if _, val, ok := extractField(line, "Vulnerability Level"); ok {
			if current != nil {
				findings = append(findings, *current)
			}
			current = &parsedFinding{}
			current.level = strings.Trim(val, "[]")
			continue
		}

		if current == nil {
			continue
		}

		if _, val, ok := extractField(line, "Issue"); ok {
			current.issue = val
		} else if _, val, ok := extractField(line, "Location"); ok {
			current.location = val
		} else if _, val, ok := extractField(line, "CVSS Vector"); ok {
			current.cvssVector = val
		} else if _, val, ok := extractField(line, "Risk"); ok {
			current.risk = val
		} else if _, val, ok := extractField(line, "Fix"); ok {
			current.fix = val
		} else if line == "---" || line == "***" {
			// separator — do nothing, next Vulnerability Level starts new finding
		} else if line != "" && current.fix != "" {
			// multi-line fix continuation
			current.fix += " " + line
		}
	}

	if current != nil {
		findings = append(findings, *current)
	}

	return findings
}

type parsedFinding struct {
	level      string
	issue      string
	location   string
	cvssVector string
	risk       string
	fix        string
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

func (p *parsedFinding) toFinding(filePath string) core.Finding {
	sev := parseLLMSeverity(p.level)
	ruleID := "broly.sast.ai." + strings.ToLower(strings.ReplaceAll(p.level, " ", "_"))

	// Extract line number from location if present (e.g., "src/main.go:42" or "line 42")
	startLine := extractLineNumber(p.location)
	description := p.risk
	if description == "" {
		description = p.issue
	}

	fix := p.fix
	cwe := extractCWE(p.issue + " " + p.risk)

	f := core.Finding{
		Type:        core.ScanTypeSAST,
		RuleID:      ruleID,
		RuleName:    p.issue,
		Severity:    sev,
		Confidence:  "high",
		Title:       p.issue,
		Description: description,
		FilePath:    filePath,
		StartLine:   startLine,
		CWE:         cwe,
		Tags:        []string{"sast", "ai"},
		Advisory:    fix,
	}

	f.ComputeFingerprint()
	return f
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
