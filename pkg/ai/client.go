// Package ai provides a shared Together.ai client for all Broly scanners.
package ai

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/togethercomputer/together-go"
	"golang.org/x/time/rate"
)

const DefaultModel = "zai-org/GLM-5.2"

var globalLimiter = rate.NewLimiter(rate.Limit(10), 20)

// Client wraps the Together.ai SDK for use by Broly scanners.
type Client struct {
	inner *together.Client
	model string
}

func (c *Client) ModelName() string {
	if c == nil {
		return ""
	}
	return c.model
}

// New returns a Client and true if TOGETHER_API_KEY is set, or nil and false otherwise.
func New(model string) (*Client, bool) {
	if os.Getenv("TOGETHER_API_KEY") == "" {
		return nil, false
	}
	if model == "" {
		model = DefaultModel
	}
	c := together.NewClient()
	return &Client{inner: &c, model: model}, true
}

// Complete sends a single-turn prompt and returns the response text.
// maxTokens controls the response length (0 = use default 2048).
func (c *Client) Complete(ctx context.Context, prompt string, maxTokens int) (string, error) {
	if err := globalLimiter.Wait(ctx); err != nil {
		return "", fmt.Errorf("rate limit: %w", err)
	}
	if maxTokens <= 0 {
		maxTokens = 2048
	}
	resp, err := c.inner.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model: together.ChatCompletionNewParamsModel(c.model),
		Messages: []together.ChatCompletionNewParamsMessageUnion{
			{
				OfChatCompletionNewsMessageChatCompletionSystemMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionSystemMessageParam{
					Role:    "system",
					Content: "You are a security expert. Follow instructions exactly. Respond with the requested format only — no preamble, no markdown formatting, no extra commentary.",
				},
			},
			{
				OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
					Role: "user",
					Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{
						OfString: together.String(prompt),
					},
				},
			},
		},
		MaxTokens: together.Int(int64(maxTokens)),
		Reasoning: together.ChatCompletionNewParamsReasoning{
			Enabled: together.Bool(false),
		},
		Temperature: together.Float(0.1),
	})
	if err != nil {
		return "", fmt.Errorf("together: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("empty response from model")
	}
	content := resp.Choices[0].Message.Content
	if strings.TrimSpace(content) == "" {
		return "", fmt.Errorf("empty content from model")
	}
	return content, nil
}
