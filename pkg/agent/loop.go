package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Shasheen8/Broly/pkg/ai"
)

const (
	DefaultMaxToolRounds    = 5
	MaxToolRequestsPerRound = 3
	MaxTotalToolExecutions  = 8
	MaxToolResultChars      = 16000
	agentLoopTimeout        = 2 * time.Minute
)

type ToolRunner interface {
	Execute(ctx context.Context, tool string, args map[string]string) (string, error)
}

type Completer interface {
	Complete(ctx context.Context, prompt string, maxTokens int) (string, error)
}

type Loop struct {
	Complete  Completer
	Tools     ToolRunner
	MaxRounds int
}

func NewLoop(client *ai.Client, tools ToolRunner, maxRounds int) *Loop {
	if maxRounds <= 0 {
		maxRounds = DefaultMaxToolRounds
	}
	return &Loop{Complete: client, Tools: tools, MaxRounds: maxRounds}
}

func (l *Loop) Run(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if l == nil || l.Complete == nil || l.Tools == nil {
		return "", fmt.Errorf("agent loop is not configured")
	}
	maxRounds := l.MaxRounds
	if maxRounds <= 0 {
		maxRounds = DefaultMaxToolRounds
	}

	conversation := strings.TrimSpace(prompt)
	var lastResponse string

	ctx, cancel := context.WithTimeout(ctx, agentLoopTimeout)
	defer cancel()

	toolExecutions := 0

	for round := 0; round < maxRounds; round++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		resp, err := l.Complete.Complete(ctx, conversation, maxTokens)
		if err != nil {
			return "", err
		}
		lastResponse = resp
		requests := ParseToolRequests(resp)
		if len(requests) == 0 {
			return resp, nil
		}
		if len(requests) > MaxToolRequestsPerRound {
			requests = requests[:MaxToolRequestsPerRound]
		}

		var toolBlock strings.Builder
		toolBlock.WriteString("\n\n---\nTool results:\n")
		for _, req := range requests {
			if toolExecutions >= MaxTotalToolExecutions {
				toolBlock.WriteString("\nNote: tool budget exhausted; respond with your VERDICT block now.\n")
				break
			}
			toolExecutions++
			result, err := l.Tools.Execute(ctx, req.Name, req.Args)
			if err != nil {
				result = "Error: " + err.Error()
			}
			result = truncateToolResult(result)
			fmt.Fprintf(&toolBlock, "\n### %s\n%s\n", req.Name, strings.TrimSpace(result))
		}
		toolBlock.WriteString("\nYou may request more tools with another TOOL: line, or respond with your final answer (VERDICT block) when ready.\n")
		conversation = conversation + toolBlock.String()
	}

	if lastResponse != "" && len(ParseToolRequests(lastResponse)) > 0 {
		conversation += "\n\nTool round limit reached. Respond with your VERDICT block only (no TOOL lines).\n"
		resp, err := l.Complete.Complete(ctx, conversation, maxTokens)
		if err != nil {
			return "", err
		}
		if len(ParseToolRequests(resp)) == 0 {
			return resp, nil
		}
		lastResponse = resp
	}

	if lastResponse != "" {
		return lastResponse, nil
	}
	return "", fmt.Errorf("agent loop exhausted %d tool rounds without a final response", maxRounds)
}

func truncateToolResult(result string) string {
	if len(result) <= MaxToolResultChars {
		return result
	}
	return result[:MaxToolResultChars] + "\n...[truncated]"
}
