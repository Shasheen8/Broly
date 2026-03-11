package triage

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

const triagePrompt = `You are a security expert triaging a code vulnerability finding.

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
2. If TRUE_POSITIVE, provide a concrete code fix — actual code, not advice.

Respond with exactly:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
REASON: One sentence.
FIX:
<2-5 lines of corrected code, or N/A if false positive>`

type Triager struct {
	client *ai.Client
}

func New(model string) *Triager {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &Triager{client: c}
}

// Run concurrently triages all findings, attaching verdict and fix suggestion to each.
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
			verdict, reason, fix := triage(ctx, t.client, &out[i])
			out[i].Verdict = verdict
			out[i].VerdictReason = reason
			out[i].FixSuggestion = fix
		}(i)
	}
	wg.Wait()
	return out
}

func triage(ctx context.Context, client *ai.Client, f *core.Finding) (verdict, reason, fix string) {
	code := fileContext(f.FilePath, f.StartLine, 8)
	prompt := fmt.Sprintf(triagePrompt,
		f.Type,
		f.RuleName,
		f.Severity.String(),
		f.Description,
		f.FilePath, f.StartLine,
		code,
	)

	resp, err := client.Complete(ctx, prompt, 512)
	if err != nil {
		return "UNKNOWN", "AI triage failed: " + err.Error(), ""
	}

	return parseTriageResponse(resp)
}

func parseTriageResponse(resp string) (verdict, reason, fix string) {
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
		if strings.HasPrefix(upper, "REASON:") {
			reason = strings.TrimSpace(trimmed[7:])
			inFix = false
			continue
		}
		if strings.HasPrefix(upper, "FIX:") {
			rest := strings.TrimSpace(trimmed[4:])
			if rest != "" && strings.ToUpper(rest) != "N/A" {
				fixLines = append(fixLines, rest)
			}
			inFix = true
			continue
		}
		if inFix && trimmed != "" && strings.ToUpper(trimmed) != "N/A" {
			fixLines = append(fixLines, trimmed)
		}
	}

	fix = strings.Join(fixLines, "\n")
	return verdict, reason, fix
}

func fileContext(path string, lineNum, radius int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	start := lineNum - radius - 1
	if start < 0 {
		start = 0
	}
	end := lineNum + radius
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		fmt.Fprintf(&sb, "%4d  %s\n", i+1, lines[i])
	}
	return sb.String()
}
