package triage

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/vasops/vulnwatch/internal/config"
)

// Anthropic is the Completer backed by the Claude Messages API with
// structured JSON output.
type Anthropic struct {
	client    anthropic.Client
	model     string
	effort    anthropic.OutputConfigEffort // empty: the model's default
	maxTokens int64

	mu    sync.Mutex // Complete may run on several goroutines
	usage Usage
}

func NewAnthropic(cfg config.Triage, apiKey string, hc *http.Client) *Anthropic {
	opts := []option.RequestOption{
		option.WithAPIKey(apiKey),
		option.WithMaxRetries(1), // after that Triage sends no further batch
	}
	if cfg.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(cfg.BaseURL))
	}
	if cfg.Timeout > 0 {
		opts = append(opts, option.WithRequestTimeout(cfg.Timeout.D()))
	}
	if hc != nil {
		opts = append(opts, option.WithHTTPClient(hc))
	}
	return &Anthropic{
		client: anthropic.NewClient(opts...), model: cfg.Model,
		effort: anthropic.OutputConfigEffort(cfg.Effort), maxTokens: int64(cfg.MaxTokens),
	}
}

func (a *Anthropic) Complete(ctx context.Context, system, user string, schema map[string]any) (string, error) {
	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     a.model,
		MaxTokens: a.maxTokens,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(user))},
		OutputConfig: anthropic.OutputConfigParam{
			Effort: a.effort,
			Format: anthropic.JSONOutputFormatParam{Schema: schema},
		},
	})
	if err != nil {
		return "", err
	}
	// Counted before the stop-reason checks: a truncated or refused answer
	// spent its tokens too.
	a.record(msg.Usage)
	switch msg.StopReason {
	case anthropic.StopReasonMaxTokens:
		return "", errors.New("model output truncated at max_tokens")
	case anthropic.StopReasonRefusal:
		return "", errors.New("model refused the request")
	}
	var sb strings.Builder
	for _, b := range msg.Content {
		if b.Type == "text" {
			sb.WriteString(b.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("no text in response (stop reason %s)", msg.StopReason)
	}
	return sb.String(), nil
}

func (a *Anthropic) record(u anthropic.Usage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.usage = a.usage.Add(Usage{
		Requests: 1, InputTokens: u.InputTokens, OutputTokens: u.OutputTokens,
		CacheCreationInputTokens: u.CacheCreationInputTokens, CacheReadInputTokens: u.CacheReadInputTokens,
	})
}

// Usage returns the total of every request answered so far.
func (a *Anthropic) Usage() Usage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.usage
}
