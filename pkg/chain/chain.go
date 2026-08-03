package chain

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Shasheen8/Broly/pkg/core"
)

const (
	maxChains              = 4
	maxPromptFindings      = 30
	maxChainTitleRunes     = 200
	maxChainNarrativeRunes = 2000
	maxChainStepRunes      = 500
)

type llmClient interface {
	Complete(ctx context.Context, prompt string, maxTokens int) (string, error)
}

func Eligible(findings []core.Finding) bool {
	input := eligibleFindings(findings)
	return eligibleMix(input)
}

func BuildExploitChains(ctx context.Context, client llmClient, findings []core.Finding) ([]core.ExploitChain, []core.Finding) {
	out := append([]core.Finding(nil), findings...)
	if client == nil || ctx.Err() != nil {
		return nil, out
	}

	input := eligibleFindings(findings)
	if !eligibleMix(input) {
		return nil, out
	}

	promptInput := input
	if len(promptInput) > maxPromptFindings {
		promptInput = topFindingsForPrompt(promptInput, maxPromptFindings)
	}

	byFingerprint, byRuleID := indexFindings(promptInput)
	promptIndex := promptIndexByPosition(promptInput)
	if len(byFingerprint) < 2 {
		return nil, out
	}

	resp, err := client.Complete(ctx, buildPrompt(promptInput), 4096)
	if err != nil {
		core.Warnf("exploit chain analysis unavailable: %v", err)
		return nil, out
	}

	parsed := parseChains(resp)
	chains := make([]core.ExploitChain, 0, min(len(parsed), maxChains))
	used := make(map[string]struct{}, maxChains)
	usedFP := make(map[string]struct{})
	for _, raw := range parsed {
		if len(chains) >= maxChains {
			break
		}
		chain, ok := validateChain(raw, byFingerprint, byRuleID, promptIndex)
		if !ok {
			continue
		}
		if _, exists := used[chain.ID]; exists {
			continue
		}
		overlap := false
		for _, fp := range chain.Fingerprints {
			if _, exists := usedFP[fp]; exists {
				overlap = true
				break
			}
		}
		if overlap {
			continue
		}
		used[chain.ID] = struct{}{}
		for _, fp := range chain.Fingerprints {
			usedFP[fp] = struct{}{}
		}
		chains = append(chains, chain)
	}
	if len(chains) == 0 {
		return nil, out
	}

	annotateFindings(&out, chains)
	return chains, out
}

func eligibleMix(input []core.Finding) bool {
	return len(input) >= 2
}

func eligibleFindings(findings []core.Finding) []core.Finding {
	out := make([]core.Finding, 0, len(findings))
	for _, f := range findings {
		if findingEligible(f) {
			out = append(out, f)
		}
	}
	return out
}

func findingEligible(f core.Finding) bool {
	if f.Severity != core.SeverityCritical {
		return false
	}
	if f.IsMaliciousPackage() {
		return true
	}
	if strings.TrimSpace(f.Verdict) != "TRUE_POSITIVE" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(f.Confidence), "HIGH") {
		return true
	}
	return f.AdversarialVerdict == "CONFIRMED"
}

func topFindingsForPrompt(findings []core.Finding, limit int) []core.Finding {
	sorted := append([]core.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		return sorted[i].PriorityScore > sorted[j].PriorityScore
	})
	if len(sorted) > limit {
		sorted = sorted[:limit]
	}
	return sorted
}

func indexFindings(findings []core.Finding) (map[string]core.Finding, map[string]string) {
	byFingerprint := make(map[string]core.Finding, len(findings))
	ruleCounts := make(map[string]int, len(findings))
	for _, f := range findings {
		fp := strings.TrimSpace(f.Fingerprint)
		if fp == "" {
			continue
		}
		byFingerprint[fp] = f
		if ruleID := strings.ToLower(strings.TrimSpace(f.RuleID)); ruleID != "" {
			ruleCounts[ruleID]++
		}
	}
	byRuleID := make(map[string]string, len(byFingerprint))
	for fp, f := range byFingerprint {
		ruleID := strings.ToLower(strings.TrimSpace(f.RuleID))
		if ruleID == "" || ruleCounts[ruleID] != 1 {
			continue
		}
		byRuleID[ruleID] = fp
	}
	return byFingerprint, byRuleID
}

func promptIndexByPosition(findings []core.Finding) map[int]string {
	out := make(map[int]string, len(findings))
	for i, f := range findings {
		if fp := strings.TrimSpace(f.Fingerprint); fp != "" {
			out[i] = fp
		}
	}
	return out
}

func buildPrompt(findings []core.Finding) string {
	var b strings.Builder
	b.WriteString(`You are an exploit development strategist reviewing PR-scoped security findings.
Your job is NOT to find new bugs. Identify 2-4 combinations of EXISTING findings that form a plausible multi-step attack chain.

Rules:
- Only link findings listed below by fingerprint or rule_id.
- Prefer chains that combine findings from different scanner types, but same-type chains are allowed when that is all that exists.
- Each chain must include at least 2 findings.
- Do not invent files, lines, packages, or findings.
- Combined severity must not exceed the highest severity among linked findings.
- Return at most 4 chains. If no plausible chain exists, return exactly: CHAINS: NONE

Respond with one or more blocks using this exact format:

CHAIN:
TITLE: short attack story title
SEVERITY: CRITICAL|HIGH|MEDIUM|LOW
FINDINGS: fingerprint-or-rule-id, fingerprint-or-rule-id
STEPS:
1. first step
2. second step
NARRATIVE: one paragraph tying the steps together

FINDINGS:
`)
	for i, f := range findings {
		fmt.Fprintf(&b, "[%d] fingerprint=%s rule_id=%s type=%s severity=%s title=%s\n", i, f.Fingerprint, f.RuleID, f.Type, f.Severity, sanitizeChainText(f.Title, maxChainTitleRunes))
		if loc := formatLocation(f); loc != "" {
			fmt.Fprintf(&b, "    location=%s\n", loc)
		}
		if desc := sanitizeChainText(f.Description, 400); desc != "" {
			fmt.Fprintf(&b, "    %s\n", desc)
		}
	}
	return b.String()
}

func formatLocation(f core.Finding) string {
	if f.PackageName != "" {
		label := f.PackageName
		if v := strings.TrimSpace(f.PackageVersion); v != "" {
			label += "@" + v
		}
		if f.FilePath != "" {
			return label + " (" + f.FilePath + ")"
		}
		return label
	}
	if f.FilePath == "" {
		return ""
	}
	if f.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.FilePath, f.StartLine)
	}
	return f.FilePath
}

type rawChain struct {
	title        string
	severity     string
	fingerprints []string
	steps        []string
	narrative    string
}

func parseChains(resp string) []rawChain {
	resp = strings.TrimSpace(resp)
	if resp == "" || chainsNoneResponse(resp) {
		return nil
	}
	blocks := strings.Split(resp, "CHAIN:")
	out := make([]rawChain, 0, maxChains)
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if raw, ok := parseChainBlock(block); ok {
			out = append(out, raw)
		}
	}
	return out
}

func chainsNoneResponse(resp string) bool {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		return upper == "CHAINS: NONE" || strings.HasPrefix(upper, "CHAINS: NONE ")
	}
	return false
}

func parseChainBlock(block string) (rawChain, bool) {
	var raw rawChain
	lines := strings.Split(block, "\n")
	inSteps := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "TITLE:"):
			raw.title = strings.TrimSpace(line[len("TITLE:"):])
			inSteps = false
		case strings.HasPrefix(upper, "SEVERITY:"):
			raw.severity = strings.TrimSpace(line[len("SEVERITY:"):])
			inSteps = false
		case strings.HasPrefix(upper, "FINDINGS:"):
			raw.fingerprints = splitList(line[len("FINDINGS:"):])
			inSteps = false
		case strings.HasPrefix(upper, "STEPS:"):
			inSteps = true
		case strings.HasPrefix(upper, "NARRATIVE:"):
			raw.narrative = strings.TrimSpace(line[len("NARRATIVE:"):])
			inSteps = false
		case inSteps:
			step := strings.TrimSpace(strings.TrimLeft(line, "0123456789.) "))
			if step != "" {
				raw.steps = append(raw.steps, step)
			}
		}
	}
	if raw.title == "" || len(raw.fingerprints) < 2 {
		return rawChain{}, false
	}
	return raw, true
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func validateChain(raw rawChain, byFingerprint map[string]core.Finding, byRuleID map[string]string, promptIndex map[int]string) (core.ExploitChain, bool) {
	resolved := make([]string, 0, len(raw.fingerprints))
	seen := make(map[string]struct{}, len(raw.fingerprints))
	maxSeverity := core.SeverityInfo
	for _, token := range raw.fingerprints {
		fp, ok := resolveToken(token, byFingerprint, byRuleID, promptIndex)
		if !ok {
			return core.ExploitChain{}, false
		}
		if _, exists := seen[fp]; exists {
			continue
		}
		seen[fp] = struct{}{}
		resolved = append(resolved, fp)
		if byFingerprint[fp].Severity > maxSeverity {
			maxSeverity = byFingerprint[fp].Severity
		}
	}
	if len(resolved) < 2 {
		return core.ExploitChain{}, false
	}
	sort.Strings(resolved)

	severity := core.ParseSeverity(raw.severity)
	if severity > maxSeverity {
		severity = maxSeverity
	}
	if severity < core.SeverityLow {
		severity = maxSeverity
	}

	steps := make([]string, 0, len(raw.steps))
	for _, step := range raw.steps {
		if cleaned := sanitizeChainText(step, maxChainStepRunes); cleaned != "" {
			steps = append(steps, cleaned)
		}
	}

	title := sanitizeChainText(raw.title, maxChainTitleRunes)
	if title == "" {
		return core.ExploitChain{}, false
	}

	return core.ExploitChain{
		ID:           chainID(resolved),
		Title:        title,
		Fingerprints: resolved,
		Steps:        steps,
		Narrative:    sanitizeChainText(raw.narrative, maxChainNarrativeRunes),
		Severity:     severity,
		Derived:      true,
	}, true
}

func resolveToken(token string, byFingerprint map[string]core.Finding, byRuleID map[string]string, promptIndex map[int]string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	token = strings.Trim(token, "[]")
	if _, ok := byFingerprint[token]; ok {
		return token, true
	}
	if fp, ok := byRuleID[strings.ToLower(token)]; ok {
		return fp, true
	}
	if idx, err := strconv.Atoi(token); err == nil {
		if fp, ok := promptIndex[idx]; ok {
			return fp, true
		}
	}
	return "", false
}

func chainID(fingerprints []string) string {
	hash := sha256.Sum256([]byte(strings.Join(fingerprints, "|")))
	return fmt.Sprintf("chain-%x", hash[:8])
}

func annotateFindings(findings *[]core.Finding, chains []core.ExploitChain) {
	chainByFingerprint := make(map[string]core.ExploitChain)
	othersByFingerprint := make(map[string][]string)
	for _, c := range chains {
		for i, fp := range c.Fingerprints {
			if _, exists := chainByFingerprint[fp]; exists {
				continue
			}
			chainByFingerprint[fp] = c
			related := make([]string, 0, len(c.Fingerprints)-1)
			for j, other := range c.Fingerprints {
				if i != j {
					related = append(related, other)
				}
			}
			othersByFingerprint[fp] = related
		}
	}
	for i := range *findings {
		fp := strings.TrimSpace((*findings)[i].Fingerprint)
		c, ok := chainByFingerprint[fp]
		if !ok {
			continue
		}
		(*findings)[i].ChainID = c.ID
		(*findings)[i].ChainedFrom = append([]string(nil), othersByFingerprint[fp]...)
	}
}

func sanitizeChainText(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "<", "")
	s = strings.ReplaceAll(s, ">", "")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	return string(runes[:maxRunes]) + "..."
}
