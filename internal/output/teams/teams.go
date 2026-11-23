// Package teams POSTs an Adaptive Card to a Microsoft Teams Workflows
// webhook: one run summary, and one card per P1 finding. The legacy format
// a Workflows webhook still accepts cannot render buttons.
package teams

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/report"
)

type Output struct {
	cfg    config.TeamsOutput
	client *httpx.Client
	url    string
	alert  string // falls back to url
	dryRun bool
	log    *slog.Logger
}

// Settings are resolved from env vars by the caller.
type Settings struct {
	URL      string
	AlertURL string // falls back to URL
	// DryRun skips every POST: no real channel sees a dry run.
	DryRun bool
}

func New(cfg config.TeamsOutput, s Settings, client *httpx.Client, log *slog.Logger) (*Output, error) {
	// cmp.Or names the YAML key when the config left the env var out.
	if s.URL == "" {
		return nil, fmt.Errorf("teams output needs %s", cmp.Or(cfg.URLEnv, "a url_env in outputs.teams"))
	}
	return &Output{cfg: cfg, client: client, url: s.URL, alert: s.AlertURL, dryRun: s.DryRun, log: log}, nil
}

func (o *Output) Name() string { return "teams" }

// Render POSTs the summary to the main URL, then one card per P1 finding to
// the alert URL (else the main URL). Every post is attempted even when
// another failed; any failure fails the run, so the state is not written and
// the next run posts everything again (at-least-once).
func (o *Output) Render(ctx context.Context, r report.Report) error {
	if o.dryRun {
		logx.Audit(ctx, o.log, "dry run: teams output skipped")
		return nil
	}
	var errs []error
	summary := buildSummaryCard(r, dashboardLink(o.cfg.DashboardURL))
	if err := o.post(ctx, o.url, summary); err != nil {
		errs = append(errs, fmt.Errorf("teams summary: %w", err))
	} else {
		logx.Audit(ctx, o.log, "teams card posted", "kind", "summary", "url", httpx.RedactURL(o.url), "total", r.Total())
	}
	alertURL := targetURL(o.url, o.alert)
	for _, it := range p1Items(r) {
		if err := o.post(ctx, alertURL, buildP1Card(it)); err != nil {
			errs = append(errs, fmt.Errorf("teams P1 %s: %w", it.ID, err))
			continue
		}
		attrs := []any{"kind", "p1_alert", "url", httpx.RedactURL(alertURL), "id", it.ID}
		if it.ScopeNames != "" {
			attrs = append(attrs, "scopes", it.ScopeNames)
		}
		logx.Audit(ctx, o.log, "teams card posted", attrs...)
	}
	return errors.Join(errs...)
}

// post sends no extra headers: the Workflows webhook URL itself carries the
// authorization. The response body is never decoded.
func (o *Output) post(ctx context.Context, url string, m message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, _, err = o.client.Do(req)
	return err
}
