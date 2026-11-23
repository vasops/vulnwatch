package pagerduty

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

// Focused unit tests for the pieces Render is built from: the dedup key and
// the per-finding event (no network, no httptest — see pagerduty_test.go for
// the end-to-end Render scenarios).

func TestDedupKeyStableForSameProductAndID(t *testing.T) {
	it := report.Item{ID: "CVE-2026-1001", Product: "keycloak"}
	a, b := dedupKey(it.Scope, it.Product, it.ID), dedupKey(it.Scope, it.Product, it.ID)
	if a == "" {
		t.Fatal("dedupKey is empty")
	}
	if a != b {
		t.Fatalf("dedupKey not stable across calls: %q != %q", a, b)
	}
}

func TestDedupKeyContainsFindingID(t *testing.T) {
	it := report.Item{ID: "CVE-2026-1001", Product: "keycloak"}
	if got := dedupKey(it.Scope, it.Product, it.ID); !strings.Contains(got, it.ID) {
		t.Errorf("dedupKey %q does not contain the finding id %q", got, it.ID)
	}
}

// Two different products hit by the same CVE must not collide, so acking
// one product's incident never silently resolves the other's.
func TestDedupKeyDiffersAcrossProductsForSameID(t *testing.T) {
	a := dedupKey("", "keycloak", "CVE-2026-1001")
	b := dedupKey("", "argocd", "CVE-2026-1001")
	if a == b {
		t.Fatalf("dedupKey collides across products for the same finding id: %q", a)
	}
}

// The same product hit by the same CVE in two tenant environments is two
// incidents: one scope's ack must not resolve the other's page.
func TestDedupKeyDiffersAcrossScopes(t *testing.T) {
	a := dedupKey("acme/prod", "keycloak", "CVE-2026-1001")
	b := dedupKey("beta/prod", "keycloak", "CVE-2026-1001")
	if a == b {
		t.Fatalf("dedupKey collides across scopes for the same finding: %q", a)
	}
}

// Without tenants the scope is empty and the key stays what it was, so
// incidents opened by earlier runs keep being updated, not duplicated.
func TestDedupKeyWithoutScopeKeepsProductAndID(t *testing.T) {
	it := report.Item{ID: "CVE-2026-1001", Product: "keycloak"}
	if got, want := dedupKey(it.Scope, it.Product, it.ID), "vulnwatch:keycloak:CVE-2026-1001"; got != want {
		t.Errorf("dedupKey = %q, want %q", got, want)
	}
}

func TestDedupKeyDiffersAcrossFindingsForSameProduct(t *testing.T) {
	a := dedupKey("", "keycloak", "CVE-2026-1001")
	b := dedupKey("", "keycloak", "CVE-2026-9999")
	if a == b {
		t.Fatalf("dedupKey collides across findings for the same product: %q", a)
	}
}

func TestP1EventMapsFindingFields(t *testing.T) {
	it := report.Item{
		ID: "CVE-2026-1001", Product: "keycloak",
		Title: "Account takeover via crafted <redirect_uri>", Priority: "P1",
	}
	ev := p1Event(it, "R0UT1NGKEY")
	if ev.EventAction != "trigger" {
		t.Errorf("event_action = %q, want trigger", ev.EventAction)
	}
	if ev.RoutingKey != "R0UT1NGKEY" {
		t.Errorf("routing_key = %q, want R0UT1NGKEY", ev.RoutingKey)
	}
	if ev.DedupKey != dedupKey(it.Scope, it.Product, it.ID) {
		t.Errorf("dedup_key = %q, want %q (dedupKey(it.Scope, it.Product, it.ID))", ev.DedupKey, dedupKey(it.Scope, it.Product, it.ID))
	}
	if ev.Payload.Severity != "critical" {
		t.Errorf("payload.severity = %q, want critical (hardcoded for every P1, not it.Severity)", ev.Payload.Severity)
	}
	if !strings.Contains(ev.Payload.Summary, it.ID) {
		t.Errorf("payload.summary = %q, want it to mention the finding id %q", ev.Payload.Summary, it.ID)
	}
	if !strings.Contains(ev.Payload.Summary, it.Title) {
		t.Errorf("payload.summary = %q, want it to mention the title %q", ev.Payload.Summary, it.Title)
	}
	if ev.Payload.Source == "" {
		t.Error("payload.source is empty")
	}
	if ev.Payload.Component != it.Product {
		t.Errorf("payload.component = %q, want the product %q", ev.Payload.Component, it.Product)
	}
}

// A tenant-scoped finding's source must say which scope, not just the bare
// product name: two tenants running the same product must be tellable apart
// in PagerDuty without opening vulnwatch.
func TestP1EventSourceUsesScope(t *testing.T) {
	it := report.Item{ID: "CVE-2026-1001", Product: "keycloak", Scope: "acme/prod"}
	ev := p1Event(it, "key")
	want := report.Named(it.Scope, it.Product)
	if ev.Payload.Source != want {
		t.Errorf("payload.source = %q, want %q (report.Named(scope, product))", ev.Payload.Source, want)
	}
}

// A dry run must never page a real on-call: Render returns before touching
// the HTTP client at all, so a nil client (as here) proves no POST was
// attempted without needing a test server.
func TestRenderSkipsOnDryRun(t *testing.T) {
	o, err := New(config.PagerDutyOutput{RoutingKeyEnv: "PAGERDUTY_ROUTING_KEY"},
		Settings{RoutingKey: "R0UT1NGKEY", DryRun: true}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
}

// New must still validate the routing key on a dry run: a misconfigured
// dry run should be caught too, same as webhook.
func TestNewStillValidatesRoutingKeyOnDryRun(t *testing.T) {
	_, err := New(config.PagerDutyOutput{RoutingKeyEnv: "PAGERDUTY_ROUTING_KEY"}, Settings{DryRun: true}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "PAGERDUTY_ROUTING_KEY") {
		t.Fatalf("want the missing-routing-key error even on a dry run, got %v", err)
	}
}

// PagerDuty rejects an event whose payload.summary is over 1024 characters,
// and a rejected event fails the run for good: not every source bounds the
// finding title, so the summary is clamped here.
func TestP1EventClampsSummaryToPagerDutyLimit(t *testing.T) {
	it := report.Item{ID: "CVE-2026-1001", Product: "keycloak", Title: strings.Repeat("very long advisory summary ", 100)}
	got := p1Event(it, "key").Payload.Summary
	if n := len([]rune(got)); n > maxSummary {
		t.Errorf("summary is %d runes, want at most %d", n, maxSummary)
	}
	if !strings.HasPrefix(got, "CVE-2026-1001: ") {
		t.Errorf("summary = %q, want it to still start with the finding id", got[:min(40, len(got))])
	}
}
