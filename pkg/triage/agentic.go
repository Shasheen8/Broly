package triage

import (
	"context"
	"fmt"
	"strings"

	"github.com/Shasheen8/Broly/pkg/agent"
	"github.com/Shasheen8/Broly/pkg/ai"
	"github.com/Shasheen8/Broly/pkg/core"
	"github.com/Shasheen8/Broly/pkg/reposearch"
)

const (
	promptVersionSASTAgentic        = "sast-agentic-v2"
	promptVersionSASTAgenticExplain = "sast-agentic-explain-v2"
)

func AgenticEligible(f *core.Finding, cloneDir string) bool {
	if cloneDir == "" || f == nil {
		return false
	}
	if f.Type != core.ScanTypeSAST {
		return false
	}
	return f.Severity >= core.SeverityHigh
}

func agenticToolInstructions() string {
	return strings.TrimSpace(`

` + reposearch.ToolDescriptions() + `

Investigation rules:
- Use TOOL: lines to read related files or search the repo before deciding.
- Trace data flow across files when the visible snippet is ambiguous.
- When you have enough evidence, respond with the VERDICT block only (no TOOL lines in the final response).
`)
}

func completeWithOptionalAgent(ctx context.Context, client *ai.Client, prompt string, maxTokens int, f *core.Finding, cloneDir string, repo *reposearch.Repo) (string, error) {
	if !AgenticEligible(f, cloneDir) {
		return client.Complete(ctx, prompt, maxTokens)
	}
	if repo == nil {
		return client.Complete(ctx, prompt, maxTokens)
	}
	loop := agent.NewLoop(client, repo, agent.DefaultMaxToolRounds)
	return loop.Run(ctx, prompt, maxTokens)
}

func (t *Triager) openRepo() (*reposearch.Repo, error) {
	if t == nil || t.cloneDir == "" {
		return nil, fmt.Errorf("no clone dir")
	}
	t.repoOnce.Do(func() {
		t.repo, t.repoErr = reposearch.New(t.cloneDir)
	})
	return t.repo, t.repoErr
}

func buildSASTTriagePromptAgentic(f *core.Finding, codeCtx string, explain bool, orgReasons []string) string {
	base := buildSASTTriagePrompt(f, codeCtx, explain, true, orgReasons)
	return base + agenticToolInstructions()
}

func promptForFindingAgentic(f *core.Finding, explain bool, cloneDir string, orgReasons []string) string {
	if !AgenticEligible(f, cloneDir) {
		return promptForFinding(f, explain, cloneDir, orgReasons)
	}

	switch f.Type {
	case core.ScanTypeContainer, core.ScanTypeSCA, core.ScanTypeWorkflow:
		return promptForFinding(f, explain, cloneDir, orgReasons)
	default:
		var codeCtx string
		absPath := safeAbsPath(cloneDir, f.FilePath)
		if f.Type == core.ScanTypeSecrets {
			if absPath == "" {
				codeCtx = fmt.Sprintf("detected value (redacted): %s", f.Redacted)
			} else {
				codeCtx = fmt.Sprintf("detected value (redacted): %s\n\nsurrounding code context:\n%s", f.Redacted, core.FileContextSafe(absPath, f.StartLine, f.EndLine, 8))
			}
		} else if absPath != "" {
			codeCtx = core.FileContext(absPath, f.StartLine, 8)
		}
		return buildSASTTriagePromptAgentic(f, codeCtx, explain, orgReasons)
	}
}
