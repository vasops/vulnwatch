package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
	"github.com/vasops/vulnwatch/internal/triage"
)

// capture is a JSON-POST-only test double: it records every body posted to
// it, decoded, and answers 200 with an empty body (Render must not decode
// the response as JSON).
func capture(t *testing.T) (*httptest.Server, *[]map[string]any) {
	t.Helper()
	var (
		mu   sync.Mutex
		gots []map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode posted body: %v", err)
		}
		gots = append(gots, body)
		w.WriteHeader(http.StatusOK)
	}))
	return srv, &gots
}

func testClient(t *testing.T) *httpx.Client {
	t.Helper()
	return httpx.New(config.HTTP{Retries: 1, RetryBackoff: config.Duration(time.Millisecond), Timeout: config.Duration(5 * time.Second)}, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func newOutput(t *testing.T, url, alertURL string) *Output {
	t.Helper()
	o, err := New(config.WebhookOutput{URLEnv: "WEBHOOK_URL", AlertURLEnv: "WEBHOOK_ALERT_URL"},
		Settings{URL: url, AlertURL: alertURL}, testClient(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// twoNonP1FindingsReport is 2 new findings, neither P1: the summary-only
// scenario must not trigger a P1 alert post, which reporttest.Sample()
// (carrying a P1 finding) would.
func twoNonP1FindingsReport() report.Report {
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	product := func(name, constraint string) catalog.Product {
		c, err := match.ParseConstraint(constraint)
		if err != nil {
			panic(err)
		}
		return catalog.Product{Name: name, Constraint: c, Exposure: "internal", Criticality: "medium"}
	}
	kc, ac := product("keycloak", "26.x"), product("argocd", "3.x")
	entries := []report.Entry{
		{
			Finding: finding.Finding{ID: "CVE-2026-3001", Product: "keycloak", Title: "Example medium issue", CVSS: 5.3, Severity: "medium", Match: "affected"},
			Product: kc,
			Triage:  triage.Result{Relevant: "yes", Priority: "P2", Method: triage.MethodRules, Summary: "x", Reasoning: "x", Action: "Check it."},
		},
		{
			Finding: finding.Finding{ID: "CVE-2026-3002", Product: "argocd", Title: "Example low issue", CVSS: 3.1, Severity: "low", Match: "affected"},
			Product: ac,
			Triage:  triage.Result{Relevant: "yes", Priority: "P3", Method: triage.MethodRules, Summary: "y", Reasoning: "y", Action: "Check it too."},
		},
	}
	return report.Build(report.Meta{
		Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now,
		Products: []catalog.Product{kc, ac},
	}, entries)
}

// Scenario: Souhrn běhu je odeslán jako jeden POST na hlavní URL.
func TestRenderPostsSummaryOnceToMainURL(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	o := newOutput(t, srv.URL, "")
	rep := twoNonP1FindingsReport()
	if total := rep.Total(); total != 2 {
		t.Fatalf("fixture precondition: want 2 new findings, got %d", total)
	}
	for _, it := range rep.Items() {
		if it.Priority == "P1" {
			t.Fatalf("fixture precondition: want no P1 finding, got %+v", rep.Items())
		}
	}
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	got := *posted
	if len(got) != 1 {
		t.Fatalf("got %d posts to the main URL, want 1: %+v", len(got), got)
	}
	if f, ok := got[0]["total"].(float64); !ok || int(f) != 2 {
		t.Errorf("summary total: %+v", got[0])
	}
	since, sok := got[0]["since"].(string)
	until, uok := got[0]["until"].(string)
	if !sok || !uok || since == "" || until == "" {
		t.Errorf("summary missing time window: %+v", got[0])
	}
}

// Scenario: P1 nález jde na alert URL, souhrn na hlavní.
func TestRenderSendsP1ToAlertURLAndSummaryToMainURL(t *testing.T) {
	main, mainPosted := capture(t)
	defer main.Close()
	alert, alertPosted := capture(t)
	defer alert.Close()
	o := newOutput(t, main.URL, alert.URL)
	rep := reporttest.Sample()
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(*mainPosted) != 1 {
		t.Fatalf("main URL got %d posts, want 1 (summary only): %+v", len(*mainPosted), *mainPosted)
	}
	ap := *alertPosted
	if len(ap) != 1 {
		t.Fatalf("alert URL got %d posts, want 1 (one P1 finding): %+v", len(ap), ap)
	}
	if prio, _ := ap[0]["priority"].(string); prio != "P1" {
		t.Errorf("alert payload priority: %+v", ap[0])
	}
	wantID := rep.Items()[0].ID // the one new P1 finding in the sample report
	if id, _ := ap[0]["id"].(string); id != wantID {
		t.Errorf("alert payload id = %q, want %q", id, wantID)
	}
}

// Scenario: Bez nastavené alert URL jde P1 na hlavní URL (fallback).
func TestRenderFallsBackToMainURLWithoutAlertURL(t *testing.T) {
	main, mainPosted := capture(t)
	defer main.Close()
	o := newOutput(t, main.URL, "")
	if err := o.Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	got := *mainPosted
	if len(got) != 2 {
		t.Fatalf("main URL got %d posts, want 2 (summary + P1): %+v", len(got), got)
	}
	sawSummary, sawP1 := false, false
	for _, p := range got {
		if _, ok := p["total"]; ok {
			sawSummary = true
		}
		if prio, _ := p["priority"].(string); prio == "P1" {
			sawP1 = true
		}
	}
	if !sawSummary || !sawP1 {
		t.Fatalf("missing summary or P1 on the main URL: %+v", got)
	}
}

// Scenario: Chybějící hlavní URL selhává na startu.
func TestNewRequiresMainURL(t *testing.T) {
	_, err := New(config.WebhookOutput{URLEnv: "WEBHOOK_URL"}, Settings{}, nil, nil)
	if err == nil {
		t.Fatal("want error for an empty main URL")
	}
	if !strings.Contains(err.Error(), "WEBHOOK_URL") {
		t.Fatalf("error should name the missing env var WEBHOOK_URL: %v", err)
	}
}

// Scenario: A configured header with no value fails at startup, instead of
// POSTing an empty Authorization and taking a 401 on every run.
func TestNewRequiresEveryConfiguredHeader(t *testing.T) {
	cfg := config.WebhookOutput{URLEnv: "WEBHOOK_URL", HeadersEnv: map[string]string{"Authorization": "WEBHOOK_AUTH_HEADER"}}
	_, err := New(cfg, Settings{URL: "https://hook.example/run"}, nil, nil)
	if err == nil {
		t.Fatal("want error for a configured header with no value")
	}
	if !strings.Contains(err.Error(), "WEBHOOK_AUTH_HEADER") || !strings.Contains(err.Error(), "Authorization") {
		t.Fatalf("error should name the header and the missing env var: %v", err)
	}
}

// Scenario: Every header resolved, New accepts it.
func TestNewAcceptsResolvedHeaders(t *testing.T) {
	cfg := config.WebhookOutput{URLEnv: "WEBHOOK_URL", HeadersEnv: map[string]string{"Authorization": "WEBHOOK_AUTH_HEADER"}}
	s := Settings{URL: "https://hook.example/run", Headers: map[string]string{"Authorization": "Bearer t0ken"}}
	if _, err := New(cfg, s, nil, nil); err != nil {
		t.Fatalf("New with every header resolved: %v", err)
	}
}

// Scenario: Trvalá chyba serveru shodí celý běh.
func TestRenderFailsAfterRetriesExhausted(t *testing.T) {
	var calls int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	o := newOutput(t, srv.URL, "")
	if err := o.Render(context.Background(), reporttest.Sample()); err == nil {
		t.Fatal("want error once the retry limit from http.retries is exhausted")
	}
	mu.Lock()
	defer mu.Unlock()
	if calls < 2 {
		t.Fatalf("want the request retried at least once, got %d calls", calls)
	}
}

// A dry run must not reach a real endpoint: one wired to a ticketing or
// paging system would otherwise get a false alert from a test run, even
// though --dry-run promises "no state writes and no Slack". New must still
// validate the URL, so a misconfigured dry run is caught too.
func TestRenderSkipsPostsOnDryRun(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	o, err := New(config.WebhookOutput{URLEnv: "WEBHOOK_URL"},
		Settings{URL: srv.URL, DryRun: true}, testClient(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	if len(*posted) != 0 {
		t.Fatalf("dry run posted %d requests, want 0: %+v", len(*posted), *posted)
	}
}

func TestNewStillValidatesURLOnDryRun(t *testing.T) {
	_, err := New(config.WebhookOutput{URLEnv: "WEBHOOK_URL"}, Settings{DryRun: true}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "WEBHOOK_URL") {
		t.Fatalf("want the missing-URL error even on a dry run, got %v", err)
	}
}
