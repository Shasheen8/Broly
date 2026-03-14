package triage

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

const triagePromptBase = `You are a security expert triaging a code vulnerability finding.

Scanner:     %s
Rule:        %s
Severity:    %s
Description: %s
File:        %s:%d

Code context:
` + "```" + `
%s
` + "```" + `

Determine:
1. Is this a TRUE_POSITIVE (real, exploitable vulnerability) or FALSE_POSITIVE (test/placeholder/safe pattern)?
2. Your confidence in that verdict.
3. If TRUE_POSITIVE, provide a concrete code fix — actual code, not advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.
FIX:
<2-5 lines of corrected code, or N/A if false positive>`

const triagePromptExplain = `You are a security expert triaging a code vulnerability finding.

Scanner:     %s
Rule:        %s
Severity:    %s
Description: %s
File:        %s:%d

Code context:
` + "```" + `
%s
` + "```" + `

Determine:
1. Is this a TRUE_POSITIVE (real, exploitable vulnerability) or FALSE_POSITIVE (test/placeholder/safe pattern)?
2. Your confidence in that verdict.
3. If TRUE_POSITIVE, provide a concrete code fix — actual code, not advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
CONFIDENCE: HIGH or MEDIUM or LOW
REASON: One sentence.
EXPLANATION: One sentence. Concrete attack vector and real-world impact specific to this code — not generic advice.
FIX:
<2-5 lines of corrected code, or N/A if false positive>`

type Triager struct {
	client  *ai.Client
	explain bool
}

func New(model string, explain bool) *Triager {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &Triager{client: c, explain: explain}
}

func (t *Triager) Run(ctx context.Context, findings []core.Finding) []core.Finding {
	out := make([]core.Finding, len(findings))
	copy(out, findings)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)

	for i := range out {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			verdict, confidence, reason, explanation, fix := triageFinding(ctx, t.client, &out[i], t.explain)
			out[i].Verdict = verdict
			out[i].Confidence = confidence
			out[i].VerdictReason = reason
			out[i].Explanation = explanation
			out[i].FixSuggestion = fix
		}(i)
	}
	wg.Wait()
	return out
}

func triageFinding(ctx context.Context, client *ai.Client, f *core.Finding, explain bool) (verdict, confidence, reason, explanation, fix string) {
	var codeCtx string
	if f.Type == core.ScanTypeSecrets {
		codeCtx = fmt.Sprintf("detected value (redacted): %s", f.Redacted)
	} else {
		codeCtx = core.FileContext(f.FilePath, f.StartLine, 8)
	}

	tmpl := triagePromptBase
	if explain {
		tmpl = triagePromptExplain
	}
	prompt := fmt.Sprintf(tmpl,
		f.Type,
		f.RuleName,
		f.Severity.String(),
		f.Description,
		f.FilePath, f.StartLine,
		codeCtx,
	)

	resp, err := client.Complete(ctx, prompt, 768)
	if err != nil {
		return "UNKNOWN", "", "AI triage failed: " + err.Error(), "", ""
	}

	return parseTriageResponse(resp)
}

func parseTriageResponse(resp string) (verdict, confidence, reason, explanation, fix string) {
	verdict = "UNKNOWN"
	var fixLines []string
	inFix := false

	for _, line := range strings.Split(resp, "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)

		if strings.HasPrefix(upper, "VERDICT:") {
			val := strings.TrimSpace(strings.TrimPrefix(upper, "VERDICT:"))
			if strings.Contains(val, "FALSE_POSITIVE") {
				verdict = "FALSE_POSITIVE"
			} else if strings.Contains(val, "TRUE_POSITIVE") {
				verdict = "TRUE_POSITIVE"
			}
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "CONFIDENCE:") {
			val := strings.TrimSpace(strings.TrimPrefix(upper, "CONFIDENCE:"))
			switch {
			case strings.Contains(val, "HIGH"):
				confidence = "HIGH"
			case strings.Contains(val, "MEDIUM"):
				confidence = "MEDIUM"
			case strings.Contains(val, "LOW"):
				confidence = "LOW"
			}
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "REASON:") {
			reason = strings.TrimSpace(trimmed[7:])
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "EXPLANATION:") {
			explanation = strings.TrimSpace(trimmed[12:])
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "FIX:") {
			rest := strings.TrimSpace(trimmed[4:])
			if rest != "" && strings.ToUpper(rest) != "N/A" && !isCodeFence(rest) {
				fixLines = append(fixLines, rest)
			}
			inFix = true
			continue
		}
		if inFix && trimmed != "" && strings.ToUpper(trimmed) != "N/A" && !isCodeFence(trimmed) {
			fixLines = append(fixLines, trimmed)
		}
	}

	fix = strings.Join(fixLines, "\n")
	return verdict, confidence, reason, explanation, fix
}

func isCodeFence(s string) bool {
	return strings.HasPrefix(s, "```")
}
