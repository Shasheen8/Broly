package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
)

const fpPrompt = `You are a security expert reviewing a potential secret detection in source code.

Rule matched: %s
File: %s
Line: %d
Detected value (redacted): %s

Surrounding code context:
` + "```" + `
%s
` + "```" + `

Determine if this is a real, active credential or a test/placeholder/example value.

FALSE POSITIVE indicators:
- File path contains: test, spec, fixture, mock, example, sample, docs, README, demo
- Value looks like a placeholder: CHANGEME, YOUR_KEY_HERE, xxx, 000000, abc123, placeholder, dummy, fake, example, insert_here, <API_KEY>
- Comments nearby indicate it is an example or documentation
- The value is clearly too short or structured to be a real credential for this rule type

TRUE POSITIVE indicators:
- High-entropy value matching the expected format and length for this credential type
- Production config, environment, or infrastructure files
- No obvious signs of being a placeholder or test value
- The value appears in code that is actively used (not commented out)

Respond with exactly two lines:
VERDICT: TRUE_POSITIVE or FALSE_POSITIVE
REASON: One sentence explanation.`

// AIValidator uses Together.ai to filter false positive secret findings.
type AIValidator struct {
	client *ai.Client
}

func newAIValidator(model string) *AIValidator {
	c, ok := ai.New(model)
	if !ok {
		return nil
	}
	return &AIValidator{client: c}
}

// validate returns true if the finding is a true positive, false if it is a false positive.
// On error it returns true (pass-through — never silently drop a finding on failure).
func (v *AIValidator) validate(ctx context.Context, f core.Finding) bool {
	context_lines := extractContext(f.FilePath, f.StartLine, 8)
	prompt := fmt.Sprintf(fpPrompt,
		f.RuleName,
		f.FilePath,
		f.StartLine,
		f.Redacted,
		context_lines,
	)

	resp, err := v.client.Complete(ctx, prompt, 256)
	if err != nil {
		return true // pass-through on error
	}

	return parseVerdict(resp)
}

// parseVerdict extracts the TRUE_POSITIVE / FALSE_POSITIVE verdict from the LLM response.
func parseVerdict(resp string) bool {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "VERDICT:") {
			val := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(line), "VERDICT:"))
			return strings.Contains(val, "TRUE_POSITIVE")
		}
	}
	return true // default: pass-through if no verdict found
}

// filterBatch concurrently validates a batch of findings, returning only true positives.
func (v *AIValidator) filterBatch(ctx context.Context, batch []core.Finding) []core.Finding {
	type result struct {
		idx int
		tp  bool
	}
	results := make([]result, len(batch))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4) // max 4 concurrent validation calls

	for i, f := range batch {
		wg.Add(1)
		go func(i int, f core.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = result{idx: i, tp: v.validate(ctx, f)}
		}(i, f)
	}
	wg.Wait()

	var out []core.Finding
	for _, r := range results {
		if r.tp {
			out = append(out, batch[r.idx])
		}
	}
	return out
}

// extractContext reads up to `radius` lines on each side of `lineNum` from the file.
func extractContext(filePath string, lineNum, radius int) string {
	data, err := os.ReadFile(filePath)
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
