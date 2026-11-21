package osv

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

func TestFetch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/query.json")
	if err != nil {
		t.Fatal(err)
	}
	var tokens []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		var q query
		if err := json.Unmarshal(b, &q); err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, q.PageToken)
		if q.PageToken == "" {
			w.Write([]byte(`{"next_page_token":"p2"}`)) // token-only page is legal
			return
		}
		w.Write(fixture)
	}))
	defer srv.Close()

	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(config.OSVSource{BaseURL: srv.URL + "/v1"}, client)
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	sel := sources.Selector{Product: "argocd", Entry: config.CatalogEntry{OSV: []config.OSVPackage{{Ecosystem: "Go", Package: "github.com/argoproj/argo-cd/v3"}}}}
	fs, err := src.Fetch(context.Background(), sel, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[1] != "p2" {
		t.Fatalf("pagination: %v", tokens)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings", len(fs))
	}
	var argo finding.Finding
	for _, f := range fs {
		if f.ID == "CVE-2025-47933" {
			argo = f
		}
	}
	if argo.ID == "" {
		t.Fatalf("canonical CVE id missing: %+v", fs)
	}
	if argo.CVSS != 9.0 || argo.Severity != finding.SeverityCritical {
		t.Fatalf("severity: %v %v", argo.CVSS, argo.Severity)
	}
	// Only the /v3 module's range applies.
	if len(argo.Affected) != 1 || argo.Affected[0] != (finding.Range{Fixed: "3.0.4"}) {
		t.Fatalf("affected: %+v", argo.Affected)
	}

	fs, err = src.Fetch(context.Background(), sel, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(fs) != 0 {
		t.Fatalf("since filter: %d %v", len(fs), err)
	}
}

func TestEventsToRanges(t *testing.T) {
	got := EventsToRanges([]map[string]string{
		{"introduced": "0"}, {"fixed": "1.2"}, {"introduced": "2.0"}, {"last_affected": "2.3"}, {"introduced": "3.0"},
	})
	want := []finding.Range{{Fixed: "1.2"}, {Introduced: "2.0", LastAffected: "2.3"}, {Introduced: "3.0"}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %+v != %+v", i, got[i], want[i])
		}
	}
}

// The Go vulnerability database marks every version of a /vN module as
// affected when it can't map the fix to a release (GO-2024-2529 for
// go.etcd.io/etcd/v3: introduced 0, no fix). That is no version data, not
// "every 3.x is affected"; a range with a start still gets the major cap.
func TestEveryVersionOfAMajorModuleIsNoData(t *testing.T) {
	var v vuln
	raw := `{"id":"GO-2024-2529","aliases":["GHSA-pm3m-32r3-7mfh"],"affected":[
		{"package":{"ecosystem":"Go","name":"go.etcd.io/etcd/v3"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]},
		{"package":{"ecosystem":"Go","name":"go.etcd.io/etcd/v3"},"ranges":[{"type":"SEMVER","events":[{"introduced":"3.5.0"}]}]}]}`
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatal(err)
	}
	f := toFinding("etcd", config.OSVPackage{Ecosystem: "Go", Package: "go.etcd.io/etcd/v3"}, v)
	want := []finding.Range{{}, {Introduced: "3.5.0", Fixed: "4.0.0"}}
	if len(f.Affected) != 2 || f.Affected[0] != want[0] || f.Affected[1] != want[1] {
		t.Fatalf("ranges %+v, want %+v", f.Affected, want)
	}
	if len(f.Fixed) != 0 {
		t.Errorf("the synthetic 4.0.0 cap is no fix: %v", f.Fixed)
	}
}
