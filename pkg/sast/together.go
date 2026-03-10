package sast

import (
	"context"

	"github.com/Shasheen8/Broly/pkg/ai"
)

type togetherClient struct {
	inner *ai.Client
}

func newTogetherClient(model string) *togetherClient {
	c, _ := ai.New(model)
	return &togetherClient{inner: c}
}

func (c *togetherClient) complete(ctx context.Context, prompt string) (string, error) {
	return c.inner.Complete(ctx, prompt, 4096)
}
