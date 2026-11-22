package ghsa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/sources"
)

func TestFetch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/advisories.json")
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/repos/argoproj/argo-cd/security-advisories" {
			t.Errorf("path %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth header %q", got)
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" || r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("headers: %v", r.Header)
		}
		if r.URL.Query().Get("after") == "" && r.URL.Query().Get("state") != "published" {
			t.Errorf("headers/query: %v %v", r.Header, r.URL.RawQuery)
		}
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<`+srv.URL+r.URL.Path+`?after=abc>; rel="next"`)
			w.Write(fixture)
			return
		}
		w.Write([]byte(`[{"ghsa_id":"GHSA-old","updated_at":"2020-01-01T00:00:00Z"}]`))
	}))
	defer srv.Close()

	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.GHSASource{BaseURL: srv.URL, TokenEnv: "T", APIVersion: "2022-11-28", PerPage: 100}, client,
		func(string) string { return "tok" }, nil)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs, err := src.Fetch(context.Background(), sources.Selector{Product: "argocd", Entry: config.CatalogEntry{GHSA: []string{"argoproj/argo-cd"}}}, since)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(fs) != 2 {
		t.Fatalf("calls=%d findings=%d", calls, len(fs))
	}
	f := fs[0]
	if f.ID != "GHSA-fw5c-w8rc-j7fx" || f.CVSS != 9.9 || f.Severity != finding.SeverityCritical || f.Product != "argocd" {
		t.Fatalf("mapping: %+v", f)
	}
	if len(f.Fixed) != 4 || len(f.Affected) != 5 {
		t.Fatalf("fixed=%v affected=%v", f.Fixed, f.Affected)
	}
	// The open ">= 2.1.0" range on the /v2 module must not match 3.x.
	for constraint, want := range map[string]match.Status{"3.4.2": match.Affected, "3.3.15": match.NotAffected, "2.9.0": match.Affected} {
		c, _ := match.ParseConstraint(constraint)
		if got := match.Match(c, f.Affected, f.AffectedVersions).Status; got != want {
			t.Errorf("%s: got %s want %s", constraint, got, want)
		}
	}
}

func TestFetchNoSelector(t *testing.T) {
	src := New(config.GHSASource{}, nil, func(string) string { return "" }, nil)
	fs, err := src.Fetch(context.Background(), sources.Selector{Product: "x"}, time.Now())
	if err != nil || fs != nil {
		t.Fatal(fs, err)
	}
}

func TestOpenRangeTakesSinglePatchedVersion(t *testing.T) {
	var a advisory
	// Envoy-style repository advisory: the range has no upper bound, the fix
	// is only in patched_versions.
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-test","vulnerabilities":[
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 1.28.0","patched_versions":"1.28.4"},
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 2.2.0-rc1","patched_versions":"3.1.2, 3.0.14"}
	]}`), &a); err != nil {
		t.Fatal(err)
	}
	f := toFinding("envoy", a)
	if len(f.Affected) != 2 || f.Affected[0] != (finding.Range{Introduced: "1.28.0", Fixed: "1.28.4"}) {
		t.Fatalf("single patched version is the fix: %+v", f.Affected)
	}
	if f.Affected[1] != (finding.Range{Introduced: "2.2.0-rc1"}) {
		t.Fatalf("several patched versions can't be attributed; the range stays open: %+v", f.Affected[1])
	}
}

func TestAllVersionsUsesPatchedVersions(t *testing.T) {
	var a advisory
	// Cilium repository advisory GHSA-6hf9-972x-wff3 (2020).
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-6hf9-972x-wff3","vulnerabilities":[
	  {"package":{"ecosystem":"","name":"cilium-proxy"},"vulnerable_version_range":"All","patched_versions":"1.5.13, 1.6.7, 1.7.1"},
	  {"package":{"ecosystem":"","name":"other"},"vulnerable_version_range":"All","patched_versions":"N/A"}
	]}`), &a); err != nil {
		t.Fatal(err)
	}
	f := toFinding("cilium", a)
	want := []finding.Range{{Fixed: "1.5.13"}, {Introduced: "1.6.0", Fixed: "1.6.7"}, {Introduced: "1.7.0", Fixed: "1.7.1"}}
	if !reflect.DeepEqual(f.Affected, want) {
		t.Fatalf("ranges from patched versions: %+v", f.Affected)
	}
	if strings.Join(f.Fixed, ",") != "1.5.13,1.6.7,1.7.1" {
		t.Fatalf("N/A is not a fixed version: %v", f.Fixed)
	}
}

func TestRangeInWords(t *testing.T) {
	var a advisory
	// MinIO repository advisory GHSA-wc79-7x8x-2p58.
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-wc79-7x8x-2p58","vulnerabilities":[
	  {"package":{"ecosystem":"","name":"MinIO Server"},"vulnerable_version_range":"RELEASE.2024-06-06T09-36-42Z and newer","patched_versions":"RELEASE.2025-02-28T09-55-16Z"}
	]}`), &a); err != nil {
		t.Fatal(err)
	}
	f := toFinding("minio", a)
	want := finding.Range{Introduced: "RELEASE.2024-06-06T09-36-42Z", Fixed: "RELEASE.2025-02-28T09-55-16Z"}
	if len(f.Affected) != 1 || f.Affected[0] != want {
		t.Fatalf("%+v", f.Affected)
	}
}

func TestSpaceSeparatedPatchedVersions(t *testing.T) {
	var a advisory
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-test","vulnerabilities":[
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":"All","patched_versions":"1.36.12 1.37.8"},
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 1.38.0","patched_versions":"1.38.6 1.39.3"},
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 1.40.0","patched_versions":"v1.40.1"},
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 1.41.0","patched_versions":"N/A"}
	]}`), &a); err != nil {
		t.Fatal(err)
	}
	f := toFinding("envoy", a)
	if strings.Join(f.Fixed, ",") != "1.36.12,1.37.8,1.38.6,1.39.3,v1.40.1" {
		t.Fatalf("fixed: %v", f.Fixed)
	}
	want := []finding.Range{{Fixed: "1.36.12"}, {Introduced: "1.37.0", Fixed: "1.37.8"}, {Introduced: "1.38.0"}, {Introduced: "1.40.0", Fixed: "v1.40.1"}, {Introduced: "1.41.0"}}
	if !reflect.DeepEqual(f.Affected, want) {
		t.Fatalf("affected: %+v", f.Affected)
	}
}

func TestCoarseRangeSplitPerBranch(t *testing.T) {
	tests := []struct {
		name, rng, patched string
		want               []finding.Range
	}{
		{"envoy", ">= 1.18.0, < 1.40.0", "1.36.10 1.37.6 1.38.4 1.39.2",
			[]finding.Range{{Introduced: "1.18.0", Fixed: "1.36.10"}, {Introduced: "1.37.0", Fixed: "1.37.6"}, {Introduced: "1.38.0", Fixed: "1.38.4"}, {Introduced: "1.39.0", Fixed: "1.39.2"}}},
		{"top fix at the bound", "< 1.33.1", "1.33.1, 1.32.4",
			[]finding.Range{{Fixed: "1.32.4"}, {Introduced: "1.33.0", Fixed: "1.33.1"}}},
		{"start inside a line", ">= 1.32.2, < 1.33.1", "1.30.9, 1.32.4, 1.33.1",
			[]finding.Range{{Introduced: "1.32.2", Fixed: "1.32.4"}, {Introduced: "1.33.0", Fixed: "1.33.1"}}},
		{"fix at the start of a later line", ">= 1.0.0, < 2.0.0", "1.5.3, 2.0.0",
			[]finding.Range{{Introduced: "1.0.0", Fixed: "1.5.3"}, {Introduced: "1.6.0", Fixed: "2.0.0"}}},
		{"line without a fix stays affected", ">= 1.0.0, <= 1.9.9", "1.4.2, 1.5.1",
			[]finding.Range{{Introduced: "1.0.0", Fixed: "1.4.2"}, {Introduced: "1.5.0", Fixed: "1.5.1"}, {Introduced: "1.6.0", LastAffected: "1.9.9"}}},
		{"one patched version", ">= 1.0.0, < 2.0.0", "2.0.0", []finding.Range{{Introduced: "1.0.0", Fixed: "2.0.0"}}},
		{"patched above the bound", ">= 1.0.0, < 1.5.0", "1.5.0, 2.0.3", []finding.Range{{Introduced: "1.0.0", Fixed: "1.5.0"}}},
		{"open range stays", ">= 2.2.0-rc1", "3.1.2, 3.0.14", []finding.Range{{Introduced: "2.2.0-rc1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a advisory
			body, _ := json.Marshal(map[string]any{"ghsa_id": "GHSA-test", "vulnerabilities": []map[string]any{
				{"vulnerable_version_range": tt.rng, "patched_versions": tt.patched},
			}})
			if err := json.Unmarshal(body, &a); err != nil {
				t.Fatal(err)
			}
			if got := toFinding("envoy", a).Affected; !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v", got)
			}
		})
	}
	// Merged with NVD's per-branch ranges, an in-branch fix is not affected.
	var a advisory
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-test","vulnerabilities":[
	  {"package":{"ecosystem":"","name":"envoy"},"vulnerable_version_range":">= 1.18.0, < 1.40.0","patched_versions":"1.36.10 1.37.6 1.38.4 1.39.2"}
	]}`), &a); err != nil {
		t.Fatal(err)
	}
	ranges := toFinding("envoy", a).Affected
	ranges = append(ranges, finding.Range{Fixed: "1.36.10"}, finding.Range{Introduced: "1.37.0", Fixed: "1.37.6"})
	for v, want := range map[string]match.Status{"1.36.10": match.NotAffected, "1.36.9": match.Affected, "1.39.1": match.Affected, "1.39.2": match.NotAffected} {
		c, _ := match.ParseConstraint(v)
		if got := match.Match(c, ranges, nil); got.Status != want {
			t.Errorf("%s: got %s (%s) want %s", v, got.Status, got.Detail, want)
		}
	}
}

func TestCVEFromText(t *testing.T) {
	cve := "CVE-2026-1"
	tests := []struct {
		name                 string
		cveID                *string
		identifiers          []string
		summary, description string
		want                 string
	}{
		{"cve_id", &cve, nil, "", "", "CVE-2026-1 GHSA-test"},
		{"identifiers", nil, []string{"GHSA-test", "CVE-2026-2"}, "", "", "CVE-2026-2 GHSA-test"},
		{"one CVE in the text", nil, nil, "Fix for cve-2026-12345", "CVE-2026-12345 allows X.", "CVE-2026-12345 GHSA-test"},
		{"several CVEs in the text", nil, nil, "", "Like CVE-2026-11111 and CVE-2026-22222.", "GHSA-test"},
		{"text ignored when cve_id is set", &cve, nil, "", "Similar to CVE-2025-99999.", "CVE-2026-1 GHSA-test"},
		{"no CVE", nil, nil, "Bug", "Nothing.", "GHSA-test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := advisory{GHSAID: "GHSA-test", CVEID: tt.cveID, Summary: tt.summary, Description: tt.description}
			for _, id := range tt.identifiers {
				a.Identifiers = append(a.Identifiers, struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				}{Value: id})
			}
			f := toFinding("x", a)
			if got := strings.Join(f.IDs(), " "); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestSeveralPackages(t *testing.T) {
	tests := []struct {
		name     string
		vulns    string // the advisory's vulnerabilities array
		note     string
		affected int
	}{
		{"server and UI with their own versions", `[
		  {"package":{"ecosystem":"npm","name":"server"},"vulnerable_version_range":"< 2.3.1","patched_versions":"2.3.1"},
		  {"package":{"ecosystem":"npm","name":"ui"},"vulnerable_version_range":"< 0.9.0","patched_versions":"0.9.0"}
		]`, "advisory covers several packages (server, ui); can't tell which one we run", 0},
		{"packages with the same versions", `[
		  {"package":{"ecosystem":"maven","name":"org.keycloak:keycloak-core"},"vulnerable_version_range":"< 26.1.4","patched_versions":"26.1.4"},
		  {"package":{"ecosystem":"maven","name":"org.keycloak:keycloak-services"},"vulnerable_version_range":"< 26.1.4","patched_versions":"26.1.4"}
		]`, "", 1},
		{"major version paths of one Go module", `[
		  {"package":{"ecosystem":"go","name":"github.com/argoproj/argo-cd/v2"},"vulnerable_version_range":">= 2.1.0","patched_versions":""},
		  {"package":{"ecosystem":"go","name":"github.com/argoproj/argo-cd/v3"},"vulnerable_version_range":"< 3.3.15","patched_versions":"3.3.15"}
		]`, "", 2},
		{"a package without version data", `[
		  {"package":{"ecosystem":"","name":"server"},"vulnerable_version_range":"< 2.3.1","patched_versions":"2.3.1"},
		  {"package":{"ecosystem":"","name":"other"},"vulnerable_version_range":"All","patched_versions":"N/A"}
		]`, "", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a advisory
			if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-test","vulnerabilities":`+tt.vulns+`}`), &a); err != nil {
				t.Fatal(err)
			}
			f := toFinding("x", a)
			if f.MatchNote != tt.note || len(f.Affected) != tt.affected {
				t.Fatalf("note=%q affected=%+v", f.MatchNote, f.Affected)
			}
			if len(f.Fixed) == 0 {
				t.Fatal("the fixed versions stay")
			}
		})
	}
}

// Real etcd advisories (2026-11-13): one entry per release line, and a
// range written in words. Neither may make a fixed version "affected".
func TestEtcdAdvisoryShapes(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      map[string]match.Status // version -> verdict
	}{
		{
			name: "one entry per release line (GHSA-xg4h-6gfc-h4m8)",
			raw: `{"ghsa_id":"GHSA-xg4h-6gfc-h4m8","vulnerabilities":[
				{"package":{"ecosystem":"go","name":"go.etcd.io/etcd/v3"},"vulnerable_version_range":"<=3.7.0","patched_versions":"3.7.1"},
				{"package":{"ecosystem":"go","name":"go.etcd.io/etcd/v3"},"vulnerable_version_range":"<=3.6.13","patched_versions":"3.6.14"},
				{"package":{"ecosystem":"go","name":"go.etcd.io/etcd/v3"},"vulnerable_version_range":"<=3.5.32","patched_versions":"3.5.33"}]}`,
			want: map[string]match.Status{"3.6.14": match.NotAffected, "3.5.33": match.NotAffected, "3.7.1": match.NotAffected,
				"3.6.13": match.Affected, "3.7.0": match.Affected, "3.5.32": match.Affected},
		},
		{
			name: "range in words (GHSA-3p4g-rcw5-8298)",
			raw: `{"ghsa_id":"GHSA-3p4g-rcw5-8298","vulnerabilities":[
				{"package":{"ecosystem":"","name":""},"vulnerable_version_range":"< v3.4.26 and < v3.5.9","patched_versions":"v3.4.26 and v3.5.9"}]}`,
			want: map[string]match.Status{"3.6.14": match.NotAffected, "3.5.9": match.NotAffected, "3.5.8": match.Affected, "3.4.25": match.Affected},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a advisory
			if err := json.Unmarshal([]byte(tc.raw), &a); err != nil {
				t.Fatal(err)
			}
			f := toFinding("etcd", a)
			for v, want := range tc.want {
				c, err := match.ParseConstraint(v)
				if err != nil {
					t.Fatal(err)
				}
				if got := match.Match(c, f.Affected, f.AffectedVersions); got.Status != want {
					t.Errorf("%s: %s (%s), want %s; ranges %v", v, got.Status, got.Detail, want, f.Affected)
				}
			}
		})
	}
}
