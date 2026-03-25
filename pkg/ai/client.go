// Package ai provides a shared Together.ai client for all Broly scanners.
package ai

import (
	"context"
	"fmt"
	"os"

	"github.com/togethercomputer/together-go"
	"golang.org/x/time/rate"
)

const DefaultModel = "Qwen/Qwen3-Coder-Next-FP8"

var globalLimiter = rate.NewLimiter(rate.Limit(10), 20)

func SetRateLimit(requestsPerSecond int, burst int) {
	globalLimiter = rate.NewLimiter(rate.Limit(requestsPerSecond), burst)
}

// Client wraps the Together.ai SDK for use by Broly scanners.
type Client struct {
	inner *together.Client
	model string
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
				OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
					Role: "user",
					Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{
						OfString: together.String(prompt),
					},
				},
			},
		},
		MaxTokens:   together.Int(int64(maxTokens)),
		Temperature: together.Float(0.1),
	})
	if err != nil {
		return "", fmt.Errorf("together: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("empty response from model")
	}
	return resp.Choices[0].Message.Content, nil
}
