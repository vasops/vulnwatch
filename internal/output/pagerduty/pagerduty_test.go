package pagerduty

import (
	"bytes"
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
// it and answers 200.
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

// pointAtTestServer redirects the package-level, otherwise-hardcoded
// enqueue URL at srv for the duration of one test.
func pointAtTestServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	orig := enqueueURL
	// Keep the path: the request the tests exercise must be the one
	// PagerDuty receives, enqueue endpoint included.
	path, ok := strings.CutPrefix(orig, "https://events.pagerduty.com")
	if !ok || path != "/v2/enqueue" {
		t.Fatalf("enqueue URL is %q, want PagerDuty's /v2/enqueue endpoint", orig)
	}
	enqueueURL = srv.URL + path
	t.Cleanup(func() { enqueueURL = orig })
}

func newOutput(t *testing.T, routingKey string, client *httpx.Client, log *slog.Logger) *Output {
	t.Helper()
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	o, err := New(config.PagerDutyOutput{RoutingKeyEnv: "PAGERDUTY_ROUTING_KEY"}, Settings{RoutingKey: routingKey}, client, log)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// twoNonP1FindingsReport is 2 new findings, neither P1: it must not trigger
// any PagerDuty event.
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

// Scenario: Nový P1 nález spustí PagerDuty event.
func TestRenderTriggersEventForNewP1Finding(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	pointAtTestServer(t, srv)
	o := newOutput(t, "R0UT1NGKEY", testClient(t), nil)
	rep := reporttest.Sample()
	wantID := rep.Items()[0].ID // the one new P1 finding in the sample report
	if rep.Items()[0].Priority != "P1" {
		t.Fatalf("fixture precondition: want a new P1 finding, got %+v", rep.Items()[0])
	}
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	got := *posted
	if len(got) != 1 {
		t.Fatalf("got %d PagerDuty events, want 1 (one new P1 finding): %+v", len(got), got)
	}
	ev := got[0]
	if action, _ := ev["event_action"].(string); action != "trigger" {
		t.Errorf("event_action = %q, want trigger", action)
	}
	if key, _ := ev["routing_key"].(string); key != "R0UT1NGKEY" {
		t.Errorf("routing_key = %q, want R0UT1NGKEY", key)
	}
	payload, ok := ev["payload"].(map[string]any)
	if !ok {
		t.Fatalf("missing payload object: %+v", ev)
	}
	if sev, _ := payload["severity"].(string); sev != "critical" {
		t.Errorf("payload.severity = %q, want critical", sev)
	}
	if summary, _ := payload["summary"].(string); summary == "" {
		t.Errorf("payload.summary is empty")
	}
	if source, _ := payload["source"].(string); source == "" {
		t.Errorf("payload.source is empty")
	}
	dedup, _ := ev["dedup_key"].(string)
	if !strings.Contains(dedup, wantID) {
		t.Errorf("dedup_key = %q, want it to contain the finding id %q", dedup, wantID)
	}
}

// Scenario: A P1 a full-history check found for the first time (a new
// tenant, a lost state) pages too, like it does on slack, webhook and teams.
func TestRenderTriggersEventForFullHistoryP1(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	pointAtTestServer(t, srv)
	o := newOutput(t, "R0UT1NGKEY", testClient(t), nil)
	rep := reporttest.Sample()
	if rep.Open[0].Priority != "P1" || rep.Open[0].FirstSeen {
		t.Fatalf("fixture precondition: want a not-yet-seen open P1 first, got %+v", rep.Open[0])
	}
	rep.Open[0].FirstSeen = true
	openID := rep.Open[0].ID
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	got := *posted
	if len(got) != 2 {
		t.Fatalf("got %d PagerDuty events, want 2 (one new P1, one from the full-history check): %+v", len(got), got)
	}
	var found bool
	for _, ev := range got {
		if dedup, _ := ev["dedup_key"].(string); strings.Contains(dedup, openID) {
			found = true
			if summary, _ := ev["payload"].(map[string]any)["summary"].(string); !strings.Contains(summary, openID) {
				t.Errorf("summary = %q, want it to name %q", summary, openID)
			}
		}
	}
	if !found {
		t.Errorf("no event for the full-history P1 %s: %+v", openID, got)
	}
}

// Scenario: Non-P1 nálezy negenerují žádný event.
func TestRenderSendsNoEventForNonP1Findings(t *testing.T) {
	srv, posted := capture(t)
	defer srv.Close()
	pointAtTestServer(t, srv)
	o := newOutput(t, "R0UT1NGKEY", testClient(t), nil)
	rep := twoNonP1FindingsReport()
	for _, it := range rep.Items() {
		if it.Priority == "P1" {
			t.Fatalf("fixture precondition: want no P1 finding, got %+v", rep.Items())
		}
	}
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if got := *posted; len(got) != 0 {
		t.Fatalf("got %d PagerDuty events, want 0 (no P1 findings): %+v", len(got), got)
	}
}

// Scenario: Chybějící routing key selhává na startu.
func TestNewRequiresRoutingKey(t *testing.T) {
	_, err := New(config.PagerDutyOutput{RoutingKeyEnv: "PAGERDUTY_ROUTING_KEY"}, Settings{}, nil, nil)
	if err == nil {
		t.Fatal("want error for an empty routing key")
	}
	if !strings.Contains(err.Error(), "PAGERDUTY_ROUTING_KEY") {
		t.Fatalf("error should name the missing env var PAGERDUTY_ROUTING_KEY: %v", err)
	}
}

// Scenario: PagerDuty odmítne event (400) shodí běh.
func TestRenderFailsWhenPagerDutyRejectsEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"status":"invalid event","message":"Event object is invalid"}`)
	}))
	defer srv.Close()
	pointAtTestServer(t, srv)
	o := newOutput(t, "R0UT1NGKEY", testClient(t), nil)
	if err := o.Render(context.Background(), reporttest.Sample()); err == nil {
		t.Fatal("want an error when PagerDuty rejects the event with 400")
	}
}

// DoD: Routing key se nikdy neobjeví v logu.
func TestRoutingKeyNeverLogged(t *testing.T) {
	srv, _ := capture(t)
	defer srv.Close()
	pointAtTestServer(t, srv)
	const secretKey = "R0UT1NG-SUPER-SECRET-KEY"
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	o := newOutput(t, secretKey, testClient(t), log)
	if err := o.Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), secretKey) {
		t.Fatalf("log contains the routing key: %s", buf.String())
	}
}

// Scenario: Without a client a real run would panic in post(), so New
// refuses it; a dry run never posts and is allowed to go without one.
func TestNewRequiresClientOutsideDryRun(t *testing.T) {
	cfg := config.PagerDutyOutput{RoutingKeyEnv: "PAGERDUTY_ROUTING_KEY"}
	if _, err := New(cfg, Settings{RoutingKey: "k"}, nil, nil); err == nil {
		t.Error("want an error for a nil client on a real run")
	}
	if _, err := New(cfg, Settings{RoutingKey: "k", DryRun: true}, nil, nil); err != nil {
		t.Errorf("a dry run needs no client: %v", err)
	}
}
