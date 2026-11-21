package nvd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/sources"
)

func TestFetch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/cves.json")
	if err != nil {
		t.Fatal(err)
	}
	var windowsSeen [][2]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("virtualMatchString") != "cpe:2.3:a:grafana:grafana" || !q.Has("noRejected") || r.Header.Get("apiKey") != "k" {
			t.Errorf("query %v header %q", q, r.Header.Get("apiKey"))
		}
		windowsSeen = append(windowsSeen, [2]string{q.Get("lastModStartDate"), q.Get("lastModEndDate")})
		if len(windowsSeen) > 1 {
			w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
			return
		}
		w.Write(fixture)
	}))
	defer srv.Close()

	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.NVDSource{
		BaseURL: srv.URL, APIKeyEnv: "K", MaxWindow: config.Duration(120 * 24 * time.Hour), ResultsPerPage: 2000,
		DetailURL: "https://nvd.example/{id}",
	}, client, func(string) string { return "k" })
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	src.now = func() time.Time { return now }
	since := now.Add(-200 * 24 * time.Hour)
	sel := sources.Selector{Product: "grafana", Entry: config.CatalogEntry{NVD: []string{"cpe:2.3:a:grafana:grafana"}}}
	fs, err := src.Fetch(context.Background(), sel, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(windowsSeen) != 2 {
		t.Fatalf("200d window should be split in two: %v", windowsSeen)
	}
	if len(fs) != 3 {
		t.Fatalf("findings: %d", len(fs))
	}
	f := fs[0]
	if f.ID != "CVE-2025-12141" || f.CVSS == 0 || f.References[0] != "https://nvd.example/CVE-2025-12141" {
		t.Fatalf("mapping: %+v", f)
	}
	if f.Modified.Format(time.RFC3339) != "2026-10-07T09:10:00Z" {
		t.Fatalf("timestamp: %v", f.Modified)
	}
	c, _ := match.ParseConstraint("12.2.x")
	if got := match.Match(c, f.Affected, f.AffectedVersions); got.Status != match.Affected {
		t.Fatalf("match: %+v (ranges %+v)", got, f.Affected)
	}
}

// decodeCVE parses one CVE record in the NVD API 2.0 shape.
func decodeCVE(t *testing.T, s string) cve {
	t.Helper()
	var c cve
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestToFindingPlatformOnly(t *testing.T) {
	const k8s = "cpe:2.3:a:kubernetes:kubernetes"
	// CVE-2026-13019: Esri Portal for ArcGIS "on Windows, Linux and
	// Kubernetes". Kubernetes is a non-vulnerable platform in an AND node;
	// the CNA data describes ArcGIS versions.
	arcgis := decodeCVE(t, `{
	  "id": "CVE-2026-13019",
	  "descriptions": [{"lang": "en", "value": "Esri Portal for ArcGIS versions 12.1 and earlier on Windows, Linux and Kubernetes ..."}],
	  "configurations": [{"nodes": [
	    {"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:esri:portal_for_arcgis:*:*:*:*:*:*:*:*", "versionEndIncluding": "12.1"}]},
	    {"cpeMatch": [{"vulnerable": false, "criteria": "cpe:2.3:a:kubernetes:kubernetes:-:*:*:*:*:*:*:*"}]}
	  ]}],
	  "affected": [{"affectedData": [{"versions": [{"version": "0", "lessThanOrEqual": "12.1", "status": "affected"}]}]}]
	}`)
	if f, ok := toFinding("kubernetes", k8s, arcgis); ok {
		t.Fatalf("platform-only CPE must not produce a finding: %+v", f)
	}

	// Our product vulnerable (all versions) next to another vulnerable
	// product: the CNA's "< 3.0" can't be attributed and must not be used.
	multi := decodeCVE(t, `{
	  "id": "CVE-2026-1",
	  "configurations": [{"nodes": [{"cpeMatch": [
	    {"vulnerable": true, "criteria": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"},
	    {"vulnerable": true, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*"}
	  ]}]}],
	  "affected": [{"affectedData": [{"versions": [{"version": "0", "lessThan": "3.0", "status": "affected"}]}]}]
	}`)
	f, ok := toFinding("kubernetes", k8s, multi)
	if !ok || len(f.Fixed) != 0 || len(f.Affected) != 1 || f.Affected[0] != (finding.Range{}) {
		t.Fatalf("multi-product CVE: ok=%v affected=%v fixed=%v", ok, f.Affected, f.Fixed)
	}
}

func TestCNAVersionsByProduct(t *testing.T) {
	const k8s = "cpe:2.3:a:kubernetes:kubernetes"
	// NVD lists both products without bounds; the CNA data has one entry per
	// product. Only our product's entry may be used.
	multi := decodeCVE(t, `{
	  "id": "CVE-2026-3",
	  "configurations": [{"nodes": [{"cpeMatch": [
	    {"vulnerable": true, "criteria": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"},
	    {"vulnerable": true, "criteria": "cpe:2.3:a:esri:portal_for_arcgis:*:*:*:*:*:*:*:*"}
	  ]}]}],
	  "affected": [{"affectedData": [
	    {"vendor": "Esri", "product": "Portal for ArcGIS", "versions": [{"version": "0", "lessThan": "12.1", "status": "affected"}]},
	    {"vendor": "Kubernetes", "product": "Kubernetes", "versions": [
	      {"version": "1.35.0", "lessThan": "1.35.6", "status": "affected"},
	      {"version": "1.34.9", "status": "affected"},
	      {"version": "abc123", "versionType": "git", "status": "affected"}
	    ]}
	  ]}]
	}`)
	f, ok := toFinding("kubernetes", k8s, multi)
	if !ok || len(f.Affected) != 1 || f.Affected[0] != (finding.Range{Introduced: "1.35.0", Fixed: "1.35.6"}) ||
		strings.Join(f.AffectedVersions, ",") != "1.34.9" || strings.Join(f.Fixed, ",") != "1.35.6" {
		t.Fatalf("our CNA entry only: ok=%v affected=%v versions=%v fixed=%v", ok, f.Affected, f.AffectedVersions, f.Fixed)
	}

	// Single product, NVD says "all versions", the CNA names the product
	// differently: the CNA range still replaces "all versions".
	single := decodeCVE(t, `{
	  "id": "CVE-2026-4",
	  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"}]}]}],
	  "affected": [{"affectedData": [{"vendor": "k8s", "product": "kube-apiserver", "versions": [{"version": "1.30.0", "lessThan": "1.30.5", "status": "affected"}]}]}]
	}`)
	if f, ok := toFinding("kubernetes", k8s, single); !ok || len(f.Affected) != 1 || f.Affected[0].Fixed != "1.30.5" {
		t.Fatalf("single-product CNA fallback: ok=%v %+v", ok, f.Affected)
	}

	// NVD's own bounded range is kept; the CNA data is not needed.
	bounded := decodeCVE(t, `{
	  "id": "CVE-2026-5",
	  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.33.2"}]}]}],
	  "affected": [{"affectedData": [{"product": "Kubernetes", "versions": [{"version": "0", "lessThan": "9.9", "status": "affected"}]}]}]
	}`)
	if f, _ := toFinding("kubernetes", k8s, bounded); len(f.Affected) != 1 || f.Affected[0].Fixed != "1.33.2" {
		t.Fatalf("NVD range must win: %+v", f.Affected)
	}
}

func TestCNANonVersions(t *testing.T) {
	const k8s = "cpe:2.3:a:kubernetes:kubernetes"
	tests := []struct {
		name     string
		versions string // CNA versions JSON
		ranges   []finding.Range
		exact    []string
	}{
		{"n/a", `[{"version": "n/a", "status": "affected"}]`, nil, nil},
		{"unspecified and junk", `[{"version": "unspecified", "status": "affected"}, {"version": "-", "status": "affected"}, {"version": "*", "status": "affected"}, {"version": "all releases", "status": "affected"}]`, nil, nil},
		{"real version kept", `[{"version": "N/A", "status": "affected"}, {"version": "1.30.2", "status": "affected"}]`, nil, []string{"1.30.2"}},
		{"n/a start of a range", `[{"version": "n/a", "lessThan": "1.30.5", "status": "affected"}]`, []finding.Range{{Fixed: "1.30.5"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := decodeCVE(t, `{"id": "CVE-2026-6",
			  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*"}]}]}],
			  "affected": [{"affectedData": [{"product": "Kubernetes", "versions": `+tt.versions+`}]}]}`)
			f, ok := toFinding("kubernetes", k8s, c)
			if !ok {
				t.Fatal("not ok")
			}
			if tt.ranges == nil && tt.exact == nil {
				if f.HasVersionData() {
					t.Fatalf("no version data expected: %+v %v", f.Affected, f.AffectedVersions)
				}
				return
			}
			if !reflect.DeepEqual(f.Affected, tt.ranges) || !reflect.DeepEqual(f.AffectedVersions, tt.exact) {
				t.Fatalf("got %+v %v", f.Affected, f.AffectedVersions)
			}
		})
	}
}

func TestPlatformConfiguration(t *testing.T) {
	const sel = "cpe:2.3:a:acme:server"
	product := `{"vulnerable": true, "criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*", "versionEndExcluding": "8.0.0"}`
	windows := `{"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}`
	tests := []struct {
		name, configurations, affected string
		want                           match.Status
		detail                         string
	}{
		{"AND with a platform", `[{"operator": "AND", "nodes": [{"operator": "OR", "cpeMatch": [` + product + `]}, {"operator": "OR", "cpeMatch": [` + windows + `]}]}]`,
			"[]", match.Unknown, "only on windows"},
		{"negated platform", `[{"operator": "AND", "nodes": [{"cpeMatch": [` + product + `]}, {"negate": true, "cpeMatch": [` + windows + `]}]}]`,
			"[]", match.Unknown, "only on not windows"},
		{"OR configuration", `[{"nodes": [{"operator": "OR", "cpeMatch": [` + product + `, ` + windows + `]}]}]`,
			"[]", match.Affected, ""},
		{"platform and a plain configuration", `[{"operator": "AND", "nodes": [{"cpeMatch": [` + product + `]}, {"cpeMatch": [` + windows + `]}]}, {"nodes": [{"cpeMatch": [` + product + `]}]}]`,
			"[]", match.Affected, ""},
		{"exact version on a platform", `[{"operator": "AND", "nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:acme:server:7.1.0:*:*:*:*:*:*:*"}]}, {"cpeMatch": [` + windows + `]}]}]`,
			"[]", match.Unknown, "only on windows"},
		{"CNA versions on a platform", `[{"operator": "AND", "nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*"}]}, {"cpeMatch": [` + windows + `]}]}]`,
			`[{"affectedData": [{"product": "server", "versions": [{"version": "0", "lessThan": "8.0.0", "status": "affected"}]}]}]`, match.Unknown, "only on windows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := decodeCVE(t, `{"id": "CVE-2026-7", "configurations": `+tt.configurations+`, "affected": `+tt.affected+`}`)
			f, ok := toFinding("server", sel, c)
			if !ok {
				t.Fatal("not ok")
			}
			cons, _ := match.ParseConstraint("7.1.0")
			res := match.Match(cons, f.Affected, f.AffectedVersions)
			if res.Status != tt.want || !strings.Contains(res.Detail, tt.detail) {
				t.Fatalf("got %s (%s), want %s; ranges %+v versions %v", res.Status, res.Detail, tt.want, f.Affected, f.AffectedVersions)
			}
		})
	}
}

func TestCNARangeInVersionString(t *testing.T) {
	// CVE-2025-27414: NVD has no configuration; GitHub as CNA writes the
	// range into the version string.
	c := decodeCVE(t, `{
	  "id": "CVE-2025-27414",
	  "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:minio:minio:*:*:*:*:*:*:*:*"}]}]}],
	  "affected": [{"affectedData": [{"vendor": "minio", "product": "minio", "versions": [
	    {"version": ">= RELEASE.2024-06-06T09-36-42Z, < RELEASE.2025-02-28T09-55-16Z", "status": "affected"}]}]}]
	}`)
	f, ok := toFinding("minio", "cpe:2.3:a:minio:minio", c)
	want := finding.Range{Introduced: "RELEASE.2024-06-06T09-36-42Z", Fixed: "RELEASE.2025-02-28T09-55-16Z"}
	if !ok || len(f.Affected) != 1 || f.Affected[0] != want || len(f.AffectedVersions) != 0 {
		t.Fatalf("range from version string: ok=%v %+v %v", ok, f.Affected, f.AffectedVersions)
	}
	cons, _ := match.ParseConstraint("RELEASE.2025-04-22T22-12-26Z")
	if res := match.Match(cons, f.Affected, f.AffectedVersions); res.Status != match.NotAffected {
		t.Fatalf("2025-04-22 is after the fix: %s", res.Status)
	}
}

func TestNormalizeName(t *testing.T) {
	for in, want := range map[string]string{
		"Portal for ArcGIS": "portal_for_arcgis", "portal_for_arcgis": "portal_for_arcgis",
		"cert-manager": "cert_manager", " GitLab ": "gitlab", "External Secrets Operator": "external_secrets_operator",
	} {
		if got := normalizeName(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestFetchFullHistory(t *testing.T) {
	fixture, err := os.ReadFile("testdata/cves.json")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if q := r.URL.Query(); q.Has("lastModStartDate") || q.Has("lastModEndDate") {
			t.Errorf("full history must not send a date range: %v", q)
		}
		w.Write(fixture)
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.NVDSource{BaseURL: srv.URL, MaxWindow: config.Duration(120 * 24 * time.Hour), ResultsPerPage: 2000},
		client, func(string) string { return "k" })
	sel := sources.Selector{Product: "grafana", Entry: config.CatalogEntry{NVD: []string{"cpe:2.3:a:grafana:grafana"}}}
	fs, err := src.Fetch(context.Background(), sel, time.Time{})
	if err != nil || len(fs) == 0 || requests != 1 {
		t.Fatalf("full history: %d findings, %d requests, err %v", len(fs), requests, err)
	}
}

// NVD turns a client's parallel requests away with 503s: however many
// products are fetched at once, at most max_in_flight requests are open.
func TestMaxInFlight(t *testing.T) {
	var open, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := open.Add(1)
		defer open.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.NVDSource{BaseURL: srv.URL, MaxWindow: config.Duration(120 * 24 * time.Hour), ResultsPerPage: 2000, MaxInFlight: 2},
		client, func(string) string { return "" })
	var wg sync.WaitGroup
	for i := range 6 {
		wg.Go(func() {
			sel := sources.Selector{Product: "p", Entry: config.CatalogEntry{NVD: []string{"cpe:2.3:a:v:p" + strings.Repeat("x", i)}}}
			if _, err := src.Fetch(context.Background(), sel, time.Time{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if p := peak.Load(); p < 1 || p > 2 {
		t.Fatalf("%d requests in flight, want at most 2", p)
	}
}

// A busy NVD must not use up run.deadline: after the budget, its requests
// fail at once (the source keeps its window for the next run).
func TestBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.Write([]byte(`{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.NVDSource{BaseURL: srv.URL, MaxWindow: config.Duration(120 * 24 * time.Hour), ResultsPerPage: 2000, Budget: config.Duration(100 * time.Millisecond)},
		client, func(string) string { return "" })
	sel := sources.Selector{Product: "p", Entry: config.CatalogEntry{NVD: []string{"cpe:2.3:a:v:p"}}}
	for i := range 2 { // cut while open, then refused at once
		start := time.Now()
		_, err := src.Fetch(context.Background(), sel, time.Time{})
		if err == nil || !strings.Contains(err.Error(), "budget of 100ms used up") || time.Since(start) > 150*time.Millisecond {
			t.Fatalf("request %d: %v after %v", i, err, time.Since(start))
		}
	}
}
