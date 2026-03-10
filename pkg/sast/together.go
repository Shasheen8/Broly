package sast

import (
	"context"
	"fmt"

	"github.com/togethercomputer/together-go"
)

type togetherClient struct {
	client *together.Client
	model  string
}

func newTogetherClient(model string) *togetherClient {
	// NewClient reads TOGETHER_API_KEY from env automatically.
	c := together.NewClient()
	return &togetherClient{client: &c, model: model}
}

// complete sends a prompt to Together.ai and returns the response text.
func (c *togetherClient) complete(ctx context.Context, prompt string) (string, error) {
	resp, err := c.client.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model: together.ChatCompletionNewParamsModel(c.model),
		Messages: []together.ChatCompletionNewParamsMessageUnion{
			{
				OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
					Role:    "user",
					Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{OfString: together.String(prompt)},
				},
			},
		},
		MaxTokens:   together.Int(4096),
		Temperature: together.Float(0.1),
	})
	if err != nil {
		return "", fmt.Errorf("together chat completion: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("empty response from model")
	}
	return resp.Choices[0].Message.Content, nil
}
