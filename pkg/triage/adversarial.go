package triage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/agent"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/reposearch"
)

const (
	maxAdversarialToolRounds = 3

	AdversarialConfirmed = "CONFIRMED"
	AdversarialDisputed  = "DISPUTED"
	AdversarialFalsified = "FALSIFIED"
)

func AdversarialEligible(f core.Finding) bool {
	if f.Severity != core.SeverityCritical {
		return false
	}
	if strings.TrimSpace(f.Verdict) != "TRUE_POSITIVE" {
		return false
	}
	return f.Type == core.ScanTypeSAST
}

func (t *Triager) RunAdversarial(ctx context.Context, findings []core.Finding) []core.Finding {
	if t == nil || t.client == nil || len(findings) == 0 || ctx.Err() != nil {
		return findings
	}

	eligible := make([]int, 0, 8)
	for i := range findings {
		if AdversarialEligible(findings[i]) {
			eligible = append(eligible, i)
		}
	}
	if len(eligible) == 0 {
		return findings
	}

	out := append([]core.Finding(nil), findings...)
	repo, repoErr := t.openRepo()
	if repoErr != nil && t.cloneDir != "" {
		core.Warnf("repo search unavailable for adversarial verify: %v", repoErr)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 2)
	for _, i := range eligible {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t.runAdversarialFinding(ctx, &out[i], repo)
		}(i)
	}
	wg.Wait()
	return out
}

func (t *Triager) runAdversarialFinding(ctx context.Context, f *core.Finding, repo *reposearch.Repo) {
	if ctx.Err() != nil {
		return
	}
	codeCtx := adversarialCodeContext(f, t.cloneDir)
	if disproven, reason := t.runFalsificationFilter(ctx, f, codeCtx); disproven {
		applyAdversarialDowngrade(f, AdversarialFalsified, reason)
		return
	}
	if ctx.Err() != nil || repo == nil || t.cloneDir == "" {
		return
	}
	status, reason := t.runFullAdversarialVerify(ctx, f, codeCtx, repo)
	switch status {
	case AdversarialDisputed:
		applyAdversarialDowngrade(f, AdversarialDisputed, reason)
	case AdversarialConfirmed:
		f.AdversarialVerdict = AdversarialConfirmed
		f.AdversarialReason = SanitizeFPReasonText(reason)
	}
}

func applyAdversarialDowngrade(f *core.Finding, status, reason string) {
	reason = SanitizeFPReasonText(reason)
	f.AdversarialVerdict = status
	f.AdversarialReason = reason
	f.Verdict = "FALSE_POSITIVE"
	f.Confidence = "HIGH"
	if reason != "" {
		f.VerdictReason = reason
		return
	}
	f.VerdictReason = "Adversarial review disproved exploitability."
}

func (t *Triager) runFalsificationFilter(ctx context.Context, f *core.Finding, codeCtx string) (disproven bool, reason string) {
	resp, err := t.client.Complete(ctx, buildFalsificationPrompt(f, codeCtx), 1024)
	if err != nil {
		core.Warnf("adversarial falsification unavailable for %s:%d: %v", f.FilePath, f.StartLine, err)
		return false, ""
	}
	return parseFalsificationResponse(resp)
}

func (t *Triager) runFullAdversarialVerify(ctx context.Context, f *core.Finding, codeCtx string, repo *reposearch.Repo) (status, reason string) {
	loop := agent.NewLoop(t.client, repo, maxAdversarialToolRounds)
	resp, err := loop.Run(ctx, buildAdversarialVerifyPrompt(f, codeCtx), 4096)
	if err != nil {
		core.Warnf("adversarial verify unavailable for %s:%d: %v", f.FilePath, f.StartLine, err)
		return "", ""
	}
	return parseAdversarialResponse(resp)
}

func adversarialCodeContext(f *core.Finding, cloneDir string) string {
	absPath := safeAbsPath(cloneDir, f.FilePath)
	if absPath == "" {
		return ""
	}
	return core.FileContext(absPath, f.StartLine, 12)
}

func appendAdversarialFindingDetails(sb *strings.Builder, f *core.Finding) {
	fmt.Fprintf(sb, "Scanner:     %s\n", f.Type)
	fmt.Fprintf(sb, "Rule:        %s\n", f.RuleName)
	fmt.Fprintf(sb, "Severity:    %s\n", f.Severity.String())
	fmt.Fprintf(sb, "Description: %s\n", f.Description)
	if f.FilePath != "" {
		fmt.Fprintf(sb, "File:        %s:%d\n", f.FilePath, f.StartLine)
	}
	if reason := SanitizeFPReasonText(f.VerdictReason); reason != "" {
		fmt.Fprintf(sb, "Triage reason: %s\n", reason)
	}
}

func buildFalsificationPrompt(f *core.Finding, codeCtx string) string {
	var sb strings.Builder
	sb.WriteString(`You are a security falsification reviewer. Prior triage marked this finding TRUE_POSITIVE.

Your job is NOT to re-triage fully. Only DISPROVE the finding when the visible code/context contains direct counter-evidence.

Rules:
- Core principle: falsify, not verify.
- DISPROVEN: YES only when visible code directly proves the security claim is wrong (hardcoded safe literal, obvious placeholder secret, code never reaches the sink, visible upstream sanitization that fully closes the path).
- DISPROVEN: NO when you merely cannot verify, when safety might depend on code outside this context, or when the visible evidence supports the finding.
- Do not guess about callers or files you cannot see.

`)
	appendAdversarialFindingDetails(&sb, f)
	if strings.TrimSpace(codeCtx) != "" {
		sb.WriteString("\nVisible context:\n```\n")
		sb.WriteString(codeCtx)
		sb.WriteString("\n```\n")
	}
	sb.WriteString(`
Respond with exactly:
DISPROVEN: YES or NO
REASON: One sentence.`)
	return sb.String()
}

func buildAdversarialVerifyPrompt(f *core.Finding, codeCtx string) string {
	var sb strings.Builder
	sb.WriteString(`You are an adversarial security verifier. A scanner and prior triage marked this finding TRUE_POSITIVE.
Assume it is WRONG until you personally confirm exploitability in the source.

Workflow:
- Read the cited code and establish what it really does.
- Trace data flow and callers across files when needed.
- Hunt for upstream validation, auth gates, framework protections, or test-only paths that fully close the issue.
- CONFIRMED only when an external or lower-privileged entry point can reach the sink with real impact.
- DISPUTED when no reachable exploit path exists or visible defenses fully neutralize the issue.

`)
	appendAdversarialFindingDetails(&sb, f)
	if strings.TrimSpace(codeCtx) != "" {
		sb.WriteString("\nInitial context:\n```\n")
		sb.WriteString(codeCtx)
		sb.WriteString("\n```\n")
	}
	sb.WriteString(agenticToolInstructions())
	sb.WriteString(`

Respond with exactly (no TOOL lines in the final response):
ADVERSARIAL_VERDICT: CONFIRMED or DISPUTED
REASON: One sentence.`)
	return sb.String()
}

func parseFalsificationResponse(resp string) (disproven bool, reason string) {
	for _, line := range strings.Split(resp, "\n") {
		label, val, ok := triageLabelValue(strings.TrimSpace(line))
		if !ok {
			continue
		}
		switch label {
		case "DISPROVEN":
			normalized := strings.ToUpper(strings.TrimSpace(val))
			disproven = strings.HasPrefix(normalized, "YES") || normalized == "TRUE"
		case "REASON":
			reason = SanitizeFPReasonText(val)
		}
	}
	return disproven, reason
}

func parseAdversarialResponse(resp string) (status, reason string) {
	for _, line := range strings.Split(resp, "\n") {
		label, val, ok := triageLabelValue(strings.TrimSpace(line))
		if !ok {
			continue
		}
		switch label {
		case "ADVERSARIAL_VERDICT":
			if parsed := parseAdversarialStatus(val); parsed != "" {
				status = parsed
			}
		case "REASON":
			reason = SanitizeFPReasonText(val)
		}
	}
	return status, reason
}

func parseAdversarialStatus(val string) string {
	normalized := strings.ToUpper(strings.TrimSpace(val))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	if strings.HasPrefix(normalized, "NOT_") || strings.HasPrefix(normalized, "UN") {
		return ""
	}
	switch normalized {
	case "DISPUTED":
		return AdversarialDisputed
	case "CONFIRMED":
		return AdversarialConfirmed
	case "FALSE_POSITIVE", "FALSEPOSITIVE":
		return AdversarialDisputed
	case "TRUE_POSITIVE", "TRUEPOSITIVE":
		return AdversarialConfirmed
	}
	return ""
}
