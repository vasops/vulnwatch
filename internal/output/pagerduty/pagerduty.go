// Package pagerduty triggers one PagerDuty Events API v2 incident per P1
// finding, straight at PagerDuty: no generic webhook in between.
package pagerduty

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
	"github.com/vasops/vulnwatch/internal/textx"
)

// enqueueURL is PagerDuty's fixed Events API v2 endpoint. It is a var only
// so tests can redirect it to an httptest.Server; nothing in config, the
// CLI or the environment can change it.
var enqueueURL = "https://events.pagerduty.com/v2/enqueue"

// maxSummary is the Events API v2 limit on payload.summary. Over it the
// event is rejected, which fails the run, leaves the state unwritten and
// fails the next run the same way: not every source bounds a finding title
// (GHSA and OSV pass the advisory summary through), so clamp it here.
const maxSummary = 1024

type Output struct {
	client     *httpx.Client
	routingKey string
	dryRun     bool
	log        *slog.Logger
}

// Settings are resolved from env vars by the caller.
type Settings struct {
	RoutingKey string
	// DryRun makes Render validate the config (New still fails on a
	// missing routing key) but skip every POST: a real PagerDuty
	// integration must never page an on-call for a test run, matching
	// --dry-run's "no state writes and no Slack".
	DryRun bool
}

// event is one PagerDuty Events API v2 request body (POST /v2/enqueue).
type event struct {
	RoutingKey  string  `json:"routing_key"`
	EventAction string  `json:"event_action"`
	DedupKey    string  `json:"dedup_key,omitempty"`
	Payload     payload `json:"payload"`
}

type payload struct {
	Summary   string `json:"summary"`
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Component string `json:"component,omitempty"`
}

func New(cfg config.PagerDutyOutput, s Settings, client *httpx.Client, log *slog.Logger) (*Output, error) {
	// cmp.Or names the YAML key when the config left the env var out: the
	// error has to say what to fix even then.
	if s.RoutingKey == "" {
		return nil, fmt.Errorf("pagerduty output needs %s", cmp.Or(cfg.RoutingKeyEnv, "a routing_key_env in outputs.pagerduty"))
	}
	// A dry run never posts, so it may be built without a client; a real
	// run would reach post() and panic on the nil instead.
	if client == nil && !s.DryRun {
		return nil, errors.New("pagerduty output needs an HTTP client outside a dry run")
	}
	return &Output{client: client, routingKey: s.RoutingKey, dryRun: s.DryRun, log: log}, nil
}

func (o *Output) Name() string { return "pagerduty" }

// Render triggers one PagerDuty event per P1 finding learned in this run:
// new or updated (r.Items()), plus every P1 a full-history check found for
// the first time (r.Open, FirstSeen) — a new tenant or a lost state must
// page too, like it does on slack, webhook and teams. Every other priority
// is silent, and so is the run summary (unlike webhook, PagerDuty is a
// page, not a report). Every event is attempted even when another failed;
// any failure fails the whole run, so the state is not written and the next
// run pages again (at-least-once, same as webhook; dedup_key keeps
// PagerDuty from opening a second incident for the same finding). A dry run
// posts nothing: a real PagerDuty integration must never page an on-call
// for a test run.
func (o *Output) Render(ctx context.Context, r report.Report) error {
	if o.dryRun {
		logx.Audit(ctx, o.log, "dry run: pagerduty output skipped")
		return nil
	}
	var errs []error
	for _, it := range r.Items() {
		if it.Priority != "P1" {
			continue
		}
		ev := p1Event(it, o.routingKey)
		if err := o.post(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("pagerduty %s: %w", it.ID, err))
			continue
		}
		logx.Audit(ctx, o.log, "pagerduty event triggered", "id", it.ID, "product", it.Product, "dedup_key", ev.DedupKey)
	}
	for _, it := range r.Open {
		if it.Priority != "P1" || !it.FirstSeen {
			continue
		}
		ev := openP1Event(it, o.routingKey)
		if err := o.post(ctx, ev); err != nil {
			errs = append(errs, fmt.Errorf("pagerduty %s: %w", it.ID, err))
			continue
		}
		logx.Audit(ctx, o.log, "pagerduty event triggered", "id", it.ID, "product", it.Product, "dedup_key", ev.DedupKey)
	}
	return errors.Join(errs...)
}

// post marshals ev and POSTs it to the fixed enqueue endpoint through the
// shared retrying client (retry on 429/5xx, TLS floor); the response body
// is read but never decoded as JSON. ev.RoutingKey never reaches a log: the
// caller only logs the finding id, product and dedup_key.
func (o *Output) post(ctx context.Context, ev event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enqueueURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	_, _, err = o.client.Do(req)
	return err
}

// dedupKey is stable for the same (scope, product, finding id) across runs,
// so a re-triggered event updates the existing PagerDuty incident instead of
// opening a new one, and never collides across products sharing a CVE. The
// scope is part of the key because the same finding in two tenant
// environments is two incidents, each acked and resolved on its own.
func dedupKey(scope, product, id string) string {
	if scope == "" {
		return fmt.Sprintf("vulnwatch:%s:%s", product, id)
	}
	return fmt.Sprintf("vulnwatch:%s:%s:%s", scope, product, id)
}

// triggerEvent builds the Events API v2 request body: severity is
// hardcoded to "critical" (a PD severity, not the CVE's CVSS severity),
// source names the scope the finding was found in (plain product name
// outside tenants), and component is the bare product.
func triggerEvent(scope, product, id, title, routingKey string) event {
	return event{
		RoutingKey:  routingKey,
		EventAction: "trigger",
		DedupKey:    dedupKey(scope, product, id),
		Payload: payload{
			Summary:   textx.Truncate(fmt.Sprintf("%s: %s", id, title), maxSummary),
			Source:    report.Named(scope, product),
			Severity:  "critical",
			Component: product,
		},
	}
}

// p1Event is triggerEvent for a P1 new or updated in this run.
func p1Event(it report.Item, routingKey string) event {
	return triggerEvent(it.Scope, it.Product, it.ID, it.Title, routingKey)
}

// openP1Event is triggerEvent for a P1 a full-history check found.
func openP1Event(it report.OpenItem, routingKey string) event {
	return triggerEvent(it.Scope, it.Product, it.ID, it.Title, routingKey)
}
