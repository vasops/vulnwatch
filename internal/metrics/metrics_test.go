package metrics

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
	"github.com/vasops/vulnwatch/internal/triage"
)

func products(t *testing.T) []catalog.Product {
	t.Helper()
	var out []catalog.Product
	for _, n := range []string{"keycloak", "argocd", "longhorn"} {
		c, _ := match.ParseConstraint("1.x")
		out = append(out, catalog.Product{Name: n, Constraint: c, Exposure: "internal", Criticality: "medium"})
	}
	return out
}

func TestRegistryFromReport(t *testing.T) {
	rep := reporttest.Sample()
	start := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	reg := Registry(Run{Mode: "run", Report: &rep, Products: products(t), Start: start, End: start.Add(90 * time.Second), LastSuccess: start})
	want := `
# HELP vulnwatch_findings_open Findings currently affecting the stack (new in this run or still open), by product and priority.
# TYPE vulnwatch_findings_open gauge
vulnwatch_findings_open{environment="default",priority="P1",product="argocd",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P1",product="keycloak",tenant="local"} 2
vulnwatch_findings_open{environment="default",priority="P1",product="longhorn",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P2",product="argocd",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P2",product="keycloak",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P2",product="longhorn",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P3",product="argocd",tenant="local"} 2
vulnwatch_findings_open{environment="default",priority="P3",product="keycloak",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P3",product="longhorn",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P4",product="argocd",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P4",product="keycloak",tenant="local"} 0
vulnwatch_findings_open{environment="default",priority="P4",product="longhorn",tenant="local"} 0
# HELP vulnwatch_findings_open_kev Open findings listed in CISA KEV (exploited in the wild), by product.
# TYPE vulnwatch_findings_open_kev gauge
vulnwatch_findings_open_kev{environment="default",product="argocd",tenant="local"} 0
vulnwatch_findings_open_kev{environment="default",product="keycloak",tenant="local"} 2
vulnwatch_findings_open_kev{environment="default",product="longhorn",tenant="local"} 0
# HELP vulnwatch_findings_open_oldest_days Days since vulnwatch first reported the oldest open finding, by product.
# TYPE vulnwatch_findings_open_oldest_days gauge
vulnwatch_findings_open_oldest_days{environment="default",product="argocd",tenant="local"} 30
vulnwatch_findings_open_oldest_days{environment="default",product="keycloak",tenant="local"} 14
vulnwatch_findings_open_oldest_days{environment="default",product="longhorn",tenant="local"} 0
# HELP vulnwatch_findings_new Findings reported in the last run (new or materially changed), by tenant, environment and priority.
# TYPE vulnwatch_findings_new gauge
vulnwatch_findings_new{environment="default",priority="P1",tenant="local"} 1
vulnwatch_findings_new{environment="default",priority="P2",tenant="local"} 0
vulnwatch_findings_new{environment="default",priority="P3",tenant="local"} 1
vulnwatch_findings_new{environment="default",priority="P4",tenant="local"} 0
# HELP vulnwatch_run_success 1 if the last run completed and every output succeeded.
# TYPE vulnwatch_run_success gauge
vulnwatch_run_success{mode="run"} 1
# HELP vulnwatch_run_duration_seconds Duration of the last run.
# TYPE vulnwatch_run_duration_seconds gauge
vulnwatch_run_duration_seconds{mode="run"} 90
# HELP vulnwatch_findings_untriaged Findings in the last run that Claude did not triage (rule-based priority).
# TYPE vulnwatch_findings_untriaged gauge
vulnwatch_findings_untriaged 1
`
	names := []string{"vulnwatch_findings_open", "vulnwatch_findings_open_kev", "vulnwatch_findings_open_oldest_days",
		"vulnwatch_findings_new", "vulnwatch_run_success", "vulnwatch_run_duration_seconds", "vulnwatch_findings_untriaged"}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), names...); err != nil {
		t.Fatal(err)
	}
	wantFindings := `
# HELP vulnwatch_finding_first_reported_timestamp_seconds Findings currently affecting the stack, one series each, with their NVD and GitHub advisory pages; the value is when vulnwatch first reported it (Unix seconds).
# TYPE vulnwatch_finding_first_reported_timestamp_seconds gauge
vulnwatch_finding_first_reported_timestamp_seconds{constraint="26.x",cvss="9.8",environment="default",fixed="26.1.4",github_url="https://example.invalid/gh/GHSA-abcd-efgh-ijkl",id="CVE-2026-1001",image="",kev="true",nvd_url="https://example.invalid/nvd/CVE-2026-1001",priority="P1",product="keycloak",severity="critical",tenant="local",title="Account takeover via crafted <redirect_uri>"} 1791784800
vulnwatch_finding_first_reported_timestamp_seconds{constraint="26.x",cvss="8.8",environment="default",fixed="",github_url="https://example.invalid/gh/GHSA-mnop-qrst-uvwx",id="CVE-2026-0900",image="",kev="true",nvd_url="https://example.invalid/nvd/CVE-2026-0900",priority="P1",product="keycloak",severity="high",tenant="local",title="Token leak in admin console"} 1790575200
vulnwatch_finding_first_reported_timestamp_seconds{constraint="3.x",cvss="6.5",environment="default",fixed="3.1.2",github_url="",id="CVE-2026-0800",image="",kev="false",nvd_url="https://example.invalid/nvd/CVE-2026-0800",priority="P3",product="argocd",severity="medium",tenant="local",title="Repo server <script> injection"} 1789192800
vulnwatch_finding_first_reported_timestamp_seconds{constraint="3.x",cvss="7.5",environment="default",fixed="3.1.8, 3.0.15",github_url="https://example.invalid/gh/GHSA-xxxx-yyyy-zzzz",id="GHSA-xxxx-yyyy-zzzz",image="",kev="false",nvd_url="",priority="P3",product="argocd",severity="high",tenant="local",title="Repo server path traversal"} 1791784800
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantFindings), "vulnwatch_finding_first_reported_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}
	wantUpgrade := `
# HELP vulnwatch_product_upgrade_info Per product with open findings: the version that fixes every open finding with a known fix; always 1.
# TYPE vulnwatch_product_upgrade_info gauge
vulnwatch_product_upgrade_info{constraint="26.x",environment="default",product="keycloak",tenant="local",upgrade_to="26.1.4"} 1
vulnwatch_product_upgrade_info{constraint="3.x",environment="default",product="argocd",tenant="local",upgrade_to="3.1.2"} 1
# HELP vulnwatch_findings_open_unfixed Open findings without any fixed version, by product.
# TYPE vulnwatch_findings_open_unfixed gauge
vulnwatch_findings_open_unfixed{environment="default",product="argocd",tenant="local"} 0
vulnwatch_findings_open_unfixed{environment="default",product="keycloak",tenant="local"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantUpgrade), "vulnwatch_product_upgrade_info", "vulnwatch_findings_open_unfixed"); err != nil {
		t.Fatal(err)
	}
	for name, n := range map[string]int{"vulnwatch_product_info": 3, "vulnwatch_findings_skipped": 4, "vulnwatch_last_success_timestamp_seconds": 1, "vulnwatch_build_info": 1} {
		if got, err := testutil.GatherAndCount(reg, name); err != nil || got != n {
			t.Errorf("%s: %d series, want %d (%v)", name, got, n, err)
		}
	}
}

func TestRegistrySingleSource(t *testing.T) {
	rep := reporttest.Sample()
	if n, err := testutil.GatherAndCount(Registry(Run{Mode: "run", Report: &rep}), "vulnwatch_findings_single_source"); err != nil || n != 0 {
		t.Fatalf("no series unless cvelist and NVD both run: %d %v", n, err)
	}
	rep.SingleSource = map[string]int{"cvelist": 3, "nvd": 0}
	want := `
# HELP vulnwatch_findings_single_source Findings in the last run only one of cvelist and NVD found, by that source (set when both run).
# TYPE vulnwatch_findings_single_source gauge
vulnwatch_findings_single_source{source="cvelist"} 3
vulnwatch_findings_single_source{source="nvd"} 0
`
	if err := testutil.GatherAndCompare(Registry(Run{Mode: "run", Report: &rep}), strings.NewReader(want), "vulnwatch_findings_single_source"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryTriageFailures(t *testing.T) {
	rep := reporttest.Sample()
	rep.TriageFailures = 2
	want := `
# HELP vulnwatch_triage_failures Claude triage calls (batches) that failed in the last run: API error, or invalid output after the retry; their findings got the rule-based priority.
# TYPE vulnwatch_triage_failures gauge
vulnwatch_triage_failures 2
`
	if err := testutil.GatherAndCompare(Registry(Run{Mode: "run", Report: &rep}), strings.NewReader(want), "vulnwatch_triage_failures"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryTriageUsage(t *testing.T) {
	rep := reporttest.Sample()
	if n, err := testutil.GatherAndCount(Registry(Run{Mode: "run", Report: &rep}), "vulnwatch_triage_requests", "vulnwatch_triage_tokens"); err != nil || n != 0 {
		t.Fatalf("no usage, no series: %d %v", n, err)
	}
	rep.TriageUsage = &report.TriageUsage{Model: "claude-test", Requests: 3, InputTokens: 1200, OutputTokens: 340, CacheReadInputTokens: 50}
	want := `
# HELP vulnwatch_triage_requests Claude triage requests that got a response in the last run, by model.
# TYPE vulnwatch_triage_requests gauge
vulnwatch_triage_requests{model="claude-test"} 3
# HELP vulnwatch_triage_tokens Tokens the Claude triage used in the last run, by model and type (input, output, cache_creation, cache_read).
# TYPE vulnwatch_triage_tokens gauge
vulnwatch_triage_tokens{model="claude-test",type="cache_creation"} 0
vulnwatch_triage_tokens{model="claude-test",type="cache_read"} 50
vulnwatch_triage_tokens{model="claude-test",type="input"} 1200
vulnwatch_triage_tokens{model="claude-test",type="output"} 340
`
	if err := testutil.GatherAndCompare(Registry(Run{Mode: "run", Report: &rep}), strings.NewReader(want), "vulnwatch_triage_requests", "vulnwatch_triage_tokens"); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryFailedRun(t *testing.T) {
	now := time.Now()
	reg := Registry(Run{Mode: "run", Err: errors.New("boom"), Products: products(t), Start: now, End: now})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP vulnwatch_run_success 1 if the last run completed and every output succeeded.
# TYPE vulnwatch_run_success gauge
vulnwatch_run_success{mode="run"} 0
`), "vulnwatch_run_success"); err != nil {
		t.Fatal(err)
	}
	if n, _ := testutil.GatherAndCount(reg, "vulnwatch_findings_open", "vulnwatch_last_success_timestamp_seconds"); n != 0 {
		t.Fatalf("a failed run without report has no finding series, got %d", n)
	}
	if !reg.HealthOnly {
		t.Fatal("a run without report must be pushed health-only")
	}
}

// A finding listed again in this run (e.g. a fix was released) keeps the
// age it had while it was open.
func TestOldestCountsRelistedFindings(t *testing.T) {
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	ps := products(t)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Products: ps}, []report.Entry{{
		Finding:       finding.Finding{ID: "CVE-2026-0001", Product: "argocd", CVSS: 7.5, Fixed: []string{"1.2.3"}, Match: "affected"},
		Product:       ps[1],
		Triage:        triage.Result{Relevant: "yes", Priority: "P2"},
		Change:        "fixed version released: 1.2.3",
		FirstReported: now.AddDate(0, 0, -30),
	}})
	reg := Registry(Run{Mode: "run", Report: &rep, Products: ps, Start: now, End: now})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP vulnwatch_findings_open_oldest_days Days since vulnwatch first reported the oldest open finding, by product.
# TYPE vulnwatch_findings_open_oldest_days gauge
vulnwatch_findings_open_oldest_days{environment="default",product="argocd",tenant="local"} 30
vulnwatch_findings_open_oldest_days{environment="default",product="keycloak",tenant="local"} 0
vulnwatch_findings_open_oldest_days{environment="default",product="longhorn",tenant="local"} 0
`), "vulnwatch_findings_open_oldest_days"); err != nil {
		t.Fatal(err)
	}
}

func TestPushAndFile(t *testing.T) {
	var method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	rep := reporttest.Sample()
	reg := Registry(Run{Mode: "run", Report: &rep, Products: products(t), Start: time.Now(), End: time.Now()})
	cfg := config.Metrics{PushgatewayURL: srv.URL, Job: "vulnwatch", Grouping: map[string]string{"instance": "prod"}, Timeout: config.Duration(5 * time.Second)}
	if err := Push(context.Background(), cfg, srv.Client(), reg); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPut || path != "/metrics/job/vulnwatch/instance/prod" || len(body) == 0 {
		t.Fatalf("push: %s %s (%d bytes)", method, path, len(body))
	}

	file := filepath.Join(t.TempDir(), "vulnwatch.prom")
	if err := WriteFile(file, reg); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(file)
	if !strings.Contains(string(b), `vulnwatch_run_success{mode="run"} 1`) {
		t.Fatalf("metrics file:\n%s", b)
	}
}

// A run that failed before its report must not replace the group: that
// would drop the open findings and resolve every finding alert. It adds
// (POST) the health families only.
func TestPushFailedRunKeepsFindings(t *testing.T) {
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.Metrics{PushgatewayURL: srv.URL, Job: "vulnwatch", Timeout: config.Duration(5 * time.Second)}
	reg := Registry(Run{Mode: "run", Err: errors.New("boom"), Products: products(t), Start: time.Now(), End: time.Now()})
	if err := Push(context.Background(), cfg, srv.Client(), reg); err != nil {
		t.Fatal(err)
	}
	if method != http.MethodPost {
		t.Fatalf("failed run pushed with %s, want POST", method)
	}
	for _, want := range []string{"vulnwatch_run_success", "vulnwatch_run_timestamp_seconds", "vulnwatch_product_info"} {
		if !strings.Contains(body, want) {
			t.Errorf("push lacks %s", want)
		}
	}
	for _, unwanted := range []string{"vulnwatch_findings_open", "vulnwatch_finding_first_reported_timestamp_seconds", "vulnwatch_findings_new"} {
		if strings.Contains(body, unwanted) {
			t.Errorf("health-only push carries %s", unwanted)
		}
	}
}

func TestRegistryTenants(t *testing.T) {
	ps := products(t)
	ps = append(ps, ps[0])
	ps[len(ps)-1].Scope = config.Scope{Tenant: "acme", Environment: "prod", Remote: true}
	reg := Registry(Run{Mode: "run", Products: ps, Start: time.Now(), End: time.Now()})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP vulnwatch_tenant_info Tenant environments being watched; local=true for the cluster vulnwatch runs in; always 1.
# TYPE vulnwatch_tenant_info gauge
vulnwatch_tenant_info{environment="default",local="true",tenant="local"} 1
vulnwatch_tenant_info{environment="prod",local="false",tenant="acme"} 1
`), "vulnwatch_tenant_info"); err != nil {
		t.Fatal(err)
	}
	if n, _ := testutil.GatherAndCount(reg, "vulnwatch_product_info"); n != len(ps) {
		t.Fatalf("product_info: %d series, want %d (one per scope)", n, len(ps))
	}
}

// The inventory age: one series per scope with a generated_at, none for
// the others; a failed run (health only) has it too.
func TestRegistryTenantInventory(t *testing.T) {
	ps := products(t)
	ps = append(ps, ps[0], ps[1])
	acme := config.Scope{Tenant: "acme", Environment: "prod", Remote: true, GeneratedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	ps[3].Scope, ps[4].Scope = acme, acme
	reg := Registry(Run{Mode: "run", Err: errors.New("boom"), Products: ps, Start: time.Now(), End: time.Now()})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP vulnwatch_tenant_inventory_timestamp_seconds When the stack of each tenant environment was read from its cluster (stack.yaml generated_at, 00:00 UTC); only for the ones that have it.
# TYPE vulnwatch_tenant_inventory_timestamp_seconds gauge
vulnwatch_tenant_inventory_timestamp_seconds{environment="prod",tenant="acme"} 1790812800
`), "vulnwatch_tenant_inventory_timestamp_seconds"); err != nil {
		t.Fatal(err)
	}
}

// findingSeries returns the per-finding series as "name{labels} value".
func findingSeries(t *testing.T, reg *Metrics) []string {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, mf := range mfs {
		if !strings.HasPrefix(mf.GetName(), "vulnwatch_finding_") {
			continue
		}
		for _, m := range mf.GetMetric() {
			var ls []string
			for _, l := range m.GetLabel() {
				ls = append(ls, l.GetName()+"="+strconv.Quote(l.GetValue()))
			}
			out = append(out, fmt.Sprintf("%s{%s} %v", mf.GetName(), strings.Join(ls, ","), m.GetGauge().GetValue()))
		}
	}
	return out
}

// One series per open finding, the first-reported timestamp, labelled with
// what the dashboard tables show: no info series and no new/open status.
func TestRegistryFindingSeries(t *testing.T) {
	rep := reporttest.Sample()
	got := findingSeries(t, Registry(Run{Mode: "run", Report: &rep, Products: products(t), Start: time.Now(), End: time.Now()}))
	if len(got) != 4 {
		t.Fatalf("%d per-finding series, want 4 (one per open finding):\n%s", len(got), strings.Join(got, "\n"))
	}
	want := `vulnwatch_finding_first_reported_timestamp_seconds{constraint="3.x",cvss="6.5",environment="default",fixed="3.1.2",` +
		`github_url="",id="CVE-2026-0800",image="",kev="false",nvd_url="https://example.invalid/nvd/CVE-2026-0800",` +
		`priority="P3",product="argocd",severity="medium",tenant="local",title="Repo server <script> injection"} 1.7891928e+09`
	if !slices.Contains(got, want) {
		t.Fatalf("missing %s in:\n%s", want, strings.Join(got, "\n"))
	}
}

// A finding reported in one run and still open in the next keeps its
// series: same labels, same value. A changed series would sit next to the
// old one in the TSDB and churn the Pushgateway.
func TestFindingSeriesStableFromNewToOpen(t *testing.T) {
	ps := products(t)
	links := report.AdvisoryLinks{NVD: "https://nvd.invalid/{id}", GitHub: "https://gh.invalid/{id}"}
	f := finding.Finding{ID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Product: "argocd", Title: "Path traversal",
		CVSS: 7.5, Severity: "high", Fixed: []string{"1.2.3"}, Match: "affected"}
	run1 := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	run2 := run1.AddDate(0, 0, 1)
	newRep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: run1, Products: ps, Links: links}, []report.Entry{{
		Finding: f, Product: ps[1], Triage: triage.Result{Relevant: "yes", Priority: "P2"},
	}})
	openRep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: run2, Products: ps, Links: links, Open: []report.OpenItem{{
		ID: f.ID, Aliases: f.Aliases, Product: f.Product, Constraint: ps[1].Constraint.String(), Title: f.Title, Fixed: f.Fixed,
		CVSS: f.CVSS, Severity: f.Severity, Match: f.Match, Priority: "P2", FirstReported: run1,
	}}}, nil)
	a := findingSeries(t, Registry(Run{Mode: "run", Report: &newRep, Products: ps, Start: run1, End: run1}))
	b := findingSeries(t, Registry(Run{Mode: "run", Report: &openRep, Products: ps, Start: run2, End: run2}))
	if len(a) != 1 || !slices.Equal(a, b) || !strings.Contains(a[0], `github_url="https://gh.invalid/GHSA-aaaa-bbbb-cccc"`) {
		t.Fatalf("new:\n%s\nopen:\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}
