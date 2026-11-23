package teams

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
// it, decoded, and answers 200 with an empty body.
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
	o, err := New(config.TeamsOutput{URLEnv: "TEAMS_URL", AlertURLEnv: "TEAMS_ALERT_URL"},
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

// Scenario: Souhrn se pošle jako jedna Adaptive Card na hlavní URL.
func TestRenderPostsSummaryAsOneAdaptiveCardToMainURL(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	o := newOutput(t, srv.URL, "")
	rep := twoNonP1FindingsReport()
	if total := rep.Total(); total != 2 {
		t.Fatalf("fixture precondition: want 2 new findings, got %d", total)
	}
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	got := *posted
	if len(got) != 1 {
		t.Fatalf("got %d posts to the main URL, want 1: %+v", len(got), got)
	}
	if typ, _ := got[0]["type"].(string); typ != "message" {
		t.Errorf("envelope type = %q, want message: %+v", typ, got[0])
	}
	card := adaptiveCardOf(t, got[0])
	if card["type"] != "AdaptiveCard" {
		t.Errorf("attachment is not an AdaptiveCard: %+v", card)
	}
	if !strings.Contains(bodyText(card), "2") {
		t.Errorf("summary text should mention the count 2: %+v", got[0])
	}
}

// Scenario: P1 nález jde na alert URL s Action.OpenUrl na odkaz na advisory.
func TestRenderSendsP1ToAlertURLWithOpenUrlAction(t *testing.T) {
	main, mainPosted := capture(t)
	defer main.Close()
	alert, alertPosted := capture(t)
	defer alert.Close()
	o := newOutput(t, main.URL, alert.URL)
	rep := reporttest.Sample()
	wantLink := rep.Items()[0].Advisories[0].URL // the one new P1 finding's advisory link
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
	actions, ok := adaptiveCardOf(t, ap[0])["actions"].([]any)
	if !ok || len(actions) == 0 {
		t.Fatalf("alert card has no actions: %+v", ap[0])
	}
	action, ok := actions[0].(map[string]any)
	if !ok || action["type"] != "Action.OpenUrl" {
		t.Fatalf("actions[0].type should be Action.OpenUrl: %+v", actions[0])
	}
	if action["url"] != wantLink {
		t.Fatalf("actions[0].url = %+v, want %q", action["url"], wantLink)
	}
}

// adaptiveCardOf digs the Adaptive Card out of the posted envelope.
func adaptiveCardOf(t *testing.T, posted map[string]any) map[string]any {
	t.Helper()
	atts, ok := posted["attachments"].([]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("want exactly one attachment: %+v", posted)
	}
	att, ok := atts[0].(map[string]any)
	if !ok || att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("attachment is not an adaptive card: %+v", atts[0])
	}
	card, ok := att["content"].(map[string]any)
	if !ok {
		t.Fatalf("attachment has no card content: %+v", att)
	}
	return card
}

// bodyText joins the card's TextBlock texts.
func bodyText(card map[string]any) string {
	var b strings.Builder
	body, _ := card["body"].([]any)
	for _, e := range body {
		el, ok := e.(map[string]any)
		if !ok || el["type"] != "TextBlock" {
			continue
		}
		if s, ok := el["text"].(string); ok {
			b.WriteString(s + " ")
		}
	}
	return b.String()
}

// Scenario: Bez alert URL jde P1 na hlavní URL (fallback).
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
}

// Scenario: Chybějící hlavní URL env selná na startu.
func TestNewRequiresMainURL(t *testing.T) {
	_, err := New(config.TeamsOutput{URLEnv: "TEAMS_URL"}, Settings{}, nil, nil)
	if err == nil {
		t.Fatal("want error for an empty main URL")
	}
	if !strings.Contains(err.Error(), "TEAMS_URL") {
		t.Fatalf("error should name the missing env var TEAMS_URL: %v", err)
	}
}

// Scenario: Trvalá chyba Teams endpointu shodí běh.
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
