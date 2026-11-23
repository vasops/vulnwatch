// Package webhook POSTs a JSON run summary, and one JSON payload per P1
// finding, to an arbitrary HTTP endpoint: routing for middleware or an
// internal system without a per-service integration.
package webhook

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/report"
)

type Output struct {
	cfg    config.WebhookOutput
	client *httpx.Client
	url    string
	alert  string // falls back to url
	header map[string]string
	dryRun bool
	log    *slog.Logger
}

// Settings are resolved from env vars by the caller.
type Settings struct {
	URL      string
	AlertURL string            // falls back to URL
	Headers  map[string]string // header name -> value
	// DryRun makes Render validate the config (New still fails on a missing
	// main URL) but skip every POST: no real endpoint sees a dry run,
	// matching --dry-run's "no state writes and no Slack".
	DryRun bool
}

// SummaryPayload is the single per-run POST: counts by priority, the new and
// open totals, the run's time window, the dashboard link and the sources
// that failed.
type SummaryPayload struct {
	Mode          string                 `json:"mode"`
	Since         string                 `json:"since"`
	Until         string                 `json:"until"`
	Total         int                    `json:"total"`
	Counts        []report.PriorityCount `json:"counts"`
	Open          []report.PriorityCount `json:"open"`
	OpenTotal     int                    `json:"open_total"`
	Dashboard     string                 `json:"dashboard,omitempty"`
	FailedSources []string               `json:"failed_sources,omitempty"`
}

// P1Payload is one P1 finding (new/updated, or found by a full-history
// check): the same data as the Slack P1 card.
type P1Payload struct {
	Priority string   `json:"priority"`
	ID       string   `json:"id"`
	Product  string   `json:"product"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss,omitempty"`
	KEV      bool     `json:"kev"`
	EPSS     float64  `json:"epss,omitempty"`
	Fixed    []string `json:"fixed,omitempty"`
	Action   string   `json:"action,omitempty"`
	Links    []string `json:"links,omitempty"`
}

func New(cfg config.WebhookOutput, s Settings, client *httpx.Client, log *slog.Logger) (*Output, error) {
	// cmp.Or names the YAML key when the config left the env var out: the
	// error has to say what to fix even then.
	if s.URL == "" {
		return nil, fmt.Errorf("webhook output needs %s", cmp.Or(cfg.URLEnv, "a url_env in outputs.webhook"))
	}
	// An unset header env var would POST an empty Authorization and come
	// back 401 on every run; name the missing variable at startup instead.
	for _, name := range slices.Sorted(maps.Keys(cfg.HeadersEnv)) {
		if s.Headers[name] == "" {
			return nil, fmt.Errorf("webhook output header %q needs %s", name, cmp.Or(cfg.HeadersEnv[name], "an env var in outputs.webhook.headers_env"))
		}
	}
	return &Output{cfg: cfg, client: client, url: s.URL, alert: s.AlertURL, header: s.Headers, dryRun: s.DryRun, log: log}, nil
}

func (o *Output) Name() string { return "webhook" }

// Render POSTs the run summary to the main URL, then one payload per P1
// finding to the alert URL (falling back to the main URL). Every post is
// attempted even when another failed; any failure fails the whole run, so
// the state is not written and the next run posts everything again
// (at-least-once). A dry run posts nothing: an endpoint wired to a
// ticketing or paging system must never see a test run's findings.
func (o *Output) Render(ctx context.Context, r report.Report) error {
	if o.dryRun {
		logx.Audit(ctx, o.log, "dry run: webhook output skipped")
		return nil
	}
	var errs []error
	dash := dashboardLink(o.cfg.DashboardURL)
	summary := buildSummary(r, dash)
	headers := headerNames(o.header)
	if err := o.post(ctx, o.url, summary); err != nil {
		errs = append(errs, fmt.Errorf("webhook summary: %w", err))
	} else {
		logx.Audit(ctx, o.log, "webhook posted", "kind", "summary", "url", httpx.RedactURL(o.url), "headers", headers, "total", summary.Total)
	}
	alertURL := targetURL(o.url, o.alert)
	for _, p := range p1Payloads(r) {
		if err := o.post(ctx, alertURL, p); err != nil {
			errs = append(errs, fmt.Errorf("webhook P1 %s: %w", p.ID, err))
			continue
		}
		logx.Audit(ctx, o.log, "webhook posted", "kind", "p1_alert", "url", httpx.RedactURL(alertURL), "headers", headers, "id", p.ID)
	}
	return errors.Join(errs...)
}

// post marshals payload and POSTs it through the shared retrying client
// (retry on 429/5xx, TLS floor, redacted URLs); the response body is read
// but never decoded as JSON.
func (o *Output) post(ctx context.Context, url string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for name, value := range o.header {
		req.Header.Set(name, value)
	}
	_, _, err = o.client.Do(req)
	return err
}

// dashboardLink fills a Grafana URL template: {from} and {to} become
// now-30d and now (the 30 days up to the click; see slack.Output.dashboardLink
// for why the window isn't fixed to the run). Empty tmpl: no link.
func dashboardLink(tmpl string) string {
	if tmpl == "" {
		return ""
	}
	return strings.NewReplacer("{from}", "now-30d", "{to}", "now").Replace(tmpl)
}

// buildSummary is the single per-run payload: counts by priority, the new
// and open totals, the run's time window, the (already resolved) dashboard
// link and the sources that failed.
func buildSummary(r report.Report, dashboard string) SummaryPayload {
	open := r.CurrentOpenCounts()
	openTotal := 0
	for _, c := range open {
		openTotal += c.Count
	}
	return SummaryPayload{
		Mode:          r.Mode,
		Since:         r.Since.Format(time.RFC3339),
		Until:         r.Until.Format(time.RFC3339),
		Total:         r.Total(),
		Counts:        r.Counts,
		Open:          open,
		OpenTotal:     openTotal,
		Dashboard:     dashboard,
		FailedSources: r.FailedSources(),
	}
}

// p1Payloads collects one payload per P1 finding learned in this run: new or
// updated (r.Items()), plus every P1 first seen by a full-history check
// (r.Open, FirstSeen). Unlike the Slack card there is no card-collapsing
// limit: a JSON payload has no section-text ceiling to fit.
func p1Payloads(r report.Report) []P1Payload {
	var out []P1Payload
	for _, it := range r.Items() {
		if it.Priority != "P1" {
			continue
		}
		out = append(out, P1Payload{
			Priority: "P1",
			ID:       it.ID,
			Product:  report.Named(it.Scope, it.Product),
			Severity: it.Severity,
			CVSS:     it.CVSS,
			KEV:      it.KEV,
			EPSS:     it.EPSS,
			Fixed:    it.Fixed,
			Action:   it.Action,
			Links:    advisoryAndOtherLinks(it.Advisories, it.Links),
		})
	}
	for _, it := range r.Open {
		if it.Priority != "P1" || !it.FirstSeen {
			continue
		}
		out = append(out, P1Payload{
			Priority: "P1",
			ID:       it.ID,
			Product:  report.Named(it.Scope, it.Product),
			Severity: it.Severity,
			CVSS:     it.CVSS,
			KEV:      it.KEV,
			EPSS:     it.EPSS,
			Fixed:    it.Fixed,
			Action:   historyAction(it),
			Links:    openItemLinks(it),
		})
	}
	return out
}

// advisoryAndOtherLinks lists the advisory page URLs (NVD, GitHub) followed
// by the finding's other references.
func advisoryAndOtherLinks(advisories []report.Advisory, refs []string) []string {
	out := make([]string, 0, len(advisories)+len(refs))
	for _, a := range advisories {
		out = append(out, a.URL)
	}
	return append(out, refs...)
}

// openItemLinks is advisoryAndOtherLinks for an OpenItem, which carries its
// one extra reference as a single Link field rather than a slice.
func openItemLinks(it report.OpenItem) []string {
	links := advisoryAndOtherLinks(it.Advisories, nil)
	if it.Link != "" && !slices.Contains(links, it.Link) {
		links = append(links, it.Link)
	}
	return links
}

// historyAction is the action text for a P1 found by a full-history check:
// Claude's action if it was triaged, else a generic one from the fixed
// versions (mirrors slack.historyAction).
func historyAction(it report.OpenItem) string {
	switch {
	case it.Action != "":
		return it.Action
	case len(it.Fixed) > 0:
		return "Upgrade to a fixed version: " + strings.Join(it.Fixed, ", ") + "."
	}
	return "No fix released yet: check the advisory for mitigations."
}

// targetURL is where a P1 alert goes: alert if set, else the main URL.
func targetURL(main, alert string) string {
	if alert != "" {
		return alert
	}
	return main
}

// headerNames lists the configured header names, for logging: never the
// values (those may be secrets, e.g. an Authorization header).
func headerNames(headers map[string]string) []string {
	out := make([]string, 0, len(headers))
	for k := range headers {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
