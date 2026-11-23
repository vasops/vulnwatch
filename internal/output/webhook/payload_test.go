package webhook

import (
	"slices"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

// Focused unit tests for the pieces Render is built from: the summary
// payload, the per-P1 payload (new/updated and full-history), the alert URL
// fallback and the header-name-only logging helper.

func TestDashboardLinkReplacesPlaceholders(t *testing.T) {
	if got := dashboardLink(""); got != "" {
		t.Fatalf("empty template: got %q, want empty (no link)", got)
	}
	tmpl := "https://grafana.example/d/vulnwatch?from={from}&to={to}"
	want := "https://grafana.example/d/vulnwatch?from=now-30d&to=now"
	if got := dashboardLink(tmpl); got != want {
		t.Fatalf("dashboardLink(%q) = %q, want %q", tmpl, got, want)
	}
}

func TestBuildSummaryMapsReportFields(t *testing.T) {
	rep := reporttest.Sample()
	const dash = "https://grafana.example/d/vulnwatch?from=now-30d&to=now"
	got := buildSummary(rep, dash)

	if got.Mode != rep.Mode {
		t.Errorf("mode = %q, want %q", got.Mode, rep.Mode)
	}
	if got.Since != rep.Since.Format(time.RFC3339) {
		t.Errorf("since = %q, want %q", got.Since, rep.Since.Format(time.RFC3339))
	}
	if got.Until != rep.Until.Format(time.RFC3339) {
		t.Errorf("until = %q, want %q", got.Until, rep.Until.Format(time.RFC3339))
	}
	if got.Total != 2 {
		t.Errorf("total = %d, want 2", got.Total)
	}
	if !slices.Equal(got.Counts, rep.Counts) {
		t.Errorf("counts = %+v, want %+v", got.Counts, rep.Counts)
	}
	open := rep.CurrentOpenCounts()
	if !slices.Equal(got.Open, open) {
		t.Errorf("open = %+v, want %+v", got.Open, open)
	}
	wantOpenTotal := 0
	for _, c := range open {
		wantOpenTotal += c.Count
	}
	if wantOpenTotal != 4 {
		t.Fatalf("fixture precondition: want 4 open, got %d", wantOpenTotal) // sanity on the fixture itself
	}
	if got.OpenTotal != wantOpenTotal {
		t.Errorf("open_total = %d, want %d", got.OpenTotal, wantOpenTotal)
	}
	if got.Dashboard != dash {
		t.Errorf("dashboard = %q, want %q", got.Dashboard, dash)
	}
	if !slices.Equal(got.FailedSources, []string{"nvd"}) {
		t.Errorf("failed_sources = %v, want [nvd]", got.FailedSources)
	}
}

func TestBuildSummaryNoFailuresNoDashboard(t *testing.T) {
	got := buildSummary(reporttest.Empty(), "")
	if got.Dashboard != "" {
		t.Errorf("dashboard = %q, want empty", got.Dashboard)
	}
	if len(got.FailedSources) != 0 {
		t.Errorf("failed_sources = %v, want none", got.FailedSources)
	}
	if got.Total != 0 {
		t.Errorf("total = %d, want 0", got.Total)
	}
}

func TestP1PayloadsNewFinding(t *testing.T) {
	rep := reporttest.Sample()
	got := p1Payloads(rep)
	if len(got) != 1 {
		t.Fatalf("got %d P1 payloads, want 1 (one new P1 finding): %+v", len(got), got)
	}
	p := got[0]
	if p.ID != "CVE-2026-1001" || p.Priority != "P1" {
		t.Fatalf("id/priority: %+v", p)
	}
	if p.Product != "keycloak" {
		t.Errorf("product = %q, want keycloak", p.Product)
	}
	if p.Severity != "critical" {
		t.Errorf("severity = %q, want critical", p.Severity)
	}
	if p.CVSS != 9.8 {
		t.Errorf("cvss = %v, want 9.8", p.CVSS)
	}
	if !p.KEV {
		t.Errorf("kev = false, want true")
	}
	if p.EPSS <= 0 {
		t.Errorf("epss = %v, want > 0", p.EPSS)
	}
	if !slices.Equal(p.Fixed, []string{"26.1.4"}) {
		t.Errorf("fixed = %v, want [26.1.4]", p.Fixed)
	}
	if p.Action != "Upgrade to 26.1.4 today." {
		t.Errorf("action = %q", p.Action)
	}
	for _, want := range []string{"https://example.invalid/nvd/CVE-2026-1001", "https://example.invalid/gh/GHSA-abcd-efgh-ijkl"} {
		if !slices.Contains(p.Links, want) {
			t.Errorf("links %v missing %q", p.Links, want)
		}
	}
}

// A P1 found by a full-history check (FirstSeen) is news too, with a
// generated action when it was never triaged (same fallback as the Slack
// P1 card's historyAction).
func TestP1PayloadsIncludesFullHistoryFind(t *testing.T) {
	rep := reporttest.Sample()
	for i := range rep.Open {
		if rep.Open[i].ID == "CVE-2026-0900" {
			rep.Open[i].FirstSeen = true
		}
	}
	got := p1Payloads(rep)
	if len(got) != 2 {
		t.Fatalf("got %d P1 payloads, want 2 (new + full-history find): %+v", len(got), got)
	}
	var history *P1Payload
	for i := range got {
		if got[i].ID == "CVE-2026-0900" {
			history = &got[i]
		}
	}
	if history == nil {
		t.Fatalf("missing the full-history P1 (CVE-2026-0900): %+v", got)
	}
	if history.Priority != "P1" {
		t.Errorf("priority = %q, want P1", history.Priority)
	}
	if history.Action != "No fix released yet: check the advisory for mitigations." {
		t.Errorf("action = %q", history.Action)
	}
}

func TestHistoryActionFallsBackByFixedVersions(t *testing.T) {
	triaged := report.OpenItem{Action: "Patch now."}
	if got := historyAction(triaged); got != "Patch now." {
		t.Errorf("triaged action = %q, want %q", got, triaged.Action)
	}
	fixed := report.OpenItem{Fixed: []string{"1.2.3", "1.1.9"}}
	if got, want := historyAction(fixed), "Upgrade to a fixed version: 1.2.3, 1.1.9."; got != want {
		t.Errorf("fixed-versions action = %q, want %q", got, want)
	}
	none := report.OpenItem{}
	if got, want := historyAction(none), "No fix released yet: check the advisory for mitigations."; got != want {
		t.Errorf("no-fix action = %q, want %q", got, want)
	}
}

func TestTargetURLFallsBackToMain(t *testing.T) {
	if got := targetURL("https://main.example", ""); got != "https://main.example" {
		t.Errorf("empty alert: got %q, want the main URL", got)
	}
	if got := targetURL("https://main.example", "https://alert.example"); got != "https://alert.example" {
		t.Errorf("set alert: got %q, want the alert URL", got)
	}
}

// headerNames must expose only names: whatever logs a webhook POST can only
// reach the header names through this helper, never the configured values.
func TestHeaderNamesNeverReturnsValues(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer super-secret-token", "X-Custom": "another-secret"}
	got := headerNames(headers)
	want := []string{"Authorization", "X-Custom"}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("names = %v, want %v", got, want)
	}
	for _, n := range got {
		if n == "Bearer super-secret-token" || n == "another-secret" {
			t.Fatalf("headerNames leaked a value: %v", got)
		}
	}
}
