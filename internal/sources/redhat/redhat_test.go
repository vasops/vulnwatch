package redhat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
)

// fakeAPI answers like the Red Hat Security Data API: ratings for the CVEs
// it knows, a detail per CVE (404 for unknown ones), 400 for CVE-BAD.
type fakeAPI struct {
	mu      sync.Mutex
	details []string // detail requests, in order
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ratings := map[string]string{"CVE-1": "Critical", "CVE-2": "moderate", "CVE-3": "important", "CVE-BAD": "low"}
	details := map[string]string{
		"CVE-1": `{"statement": "Only servers with HTTP/2 enabled are affected.", "mitigation": {"value": "Disable HTTP/2.", "lang": "en:us"}}`,
		"CVE-3": `{"statement": "", "mitigation": "Restrict access to the admin port."}`,
	}
	switch {
	case r.URL.Path == "/cve.json":
		var out []string
		for _, id := range strings.Split(r.URL.Query().Get("ids"), ",") {
			if s, ok := ratings[id]; ok {
				out = append(out, `{"CVE": "`+id+`", "severity": "`+s+`"}`)
			}
		}
		w.Write([]byte("[" + strings.Join(out, ",") + "]"))
	case strings.HasPrefix(r.URL.Path, "/cve/"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/cve/"), ".json")
		a.mu.Lock()
		a.details = append(a.details, id)
		a.mu.Unlock()
		if id == "CVE-BAD" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		d, ok := details[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(d))
	default:
		http.NotFound(w, r)
	}
}

func enrich(t *testing.T, cfg config.RedHatSource, fs []finding.Finding) (*fakeAPI, error) {
	t.Helper()
	api := &fakeAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	return api, New(cfg, client).Enrich(context.Background(), fs)
}

func TestEnrich(t *testing.T) {
	fs := []finding.Finding{
		{ID: "CVE-1", KEV: true},
		{ID: "GHSA-x", Aliases: []string{"CVE-2"}}, // known, no detail (404)
		{ID: "CVE-3"},                              // mitigation as a plain string
		{ID: "CVE-404"},                            // unknown to Red Hat
		{ID: "GHSA-nocve"},
	}
	api, err := enrich(t, config.RedHatSource{BatchSize: 2, MaxDetails: 10}, fs)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ sev, statement, mitigation string }{
		{"critical", "Only servers with HTTP/2 enabled are affected.", "Disable HTTP/2."},
		{"moderate", "", ""},
		{"important", "", "Restrict access to the admin port."},
		{"", "", ""},
		{"", "", ""},
	}
	for i, w := range want {
		f := fs[i]
		if f.RedHatSeverity != w.sev || f.RedHatStatement != w.statement || f.RedHatMitigation != w.mitigation {
			t.Errorf("%s: got %q %q %q, want %q %q %q", f.ID, f.RedHatSeverity, f.RedHatStatement, f.RedHatMitigation, w.sev, w.statement, w.mitigation)
		}
	}
	if slices.Contains(api.details, "CVE-404") {
		t.Errorf("detail fetched for a CVE Red Hat doesn't know: %v", api.details)
	}
}

func TestDetailsMostUrgentFirstAndCapped(t *testing.T) {
	fs := []finding.Finding{
		{ID: "CVE-2", CVSS: 9.8},
		{ID: "CVE-3", EPSS: 0.5},
		{ID: "CVE-1", KEV: true},
	}
	api, err := enrich(t, config.RedHatSource{BatchSize: 50, MaxDetails: 2}, fs)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"CVE-1", "CVE-3"}; !slices.Equal(api.details, want) {
		t.Fatalf("details %v, want %v (KEV, then EPSS; capped at 2)", api.details, want)
	}
	if fs[0].RedHatSeverity != "moderate" {
		t.Errorf("rating without a fetched statement still applies: %+v", fs[0])
	}
}

func TestFailedDetailKeepsRatings(t *testing.T) {
	fs := []finding.Finding{{ID: "CVE-BAD"}, {ID: "CVE-1"}}
	_, err := enrich(t, config.RedHatSource{BatchSize: 50, MaxDetails: 10}, fs)
	if err == nil {
		t.Fatal("want the failed detail request as an error")
	}
	if fs[0].RedHatSeverity != "low" || fs[1].RedHatStatement == "" {
		t.Fatalf("ratings and the other statement must still apply: %+v", fs)
	}
}

func TestMergeKeepsTheMostSevereRating(t *testing.T) {
	m := finding.Dedup([]finding.Finding{
		{ID: "CVE-1", Product: "p", RedHatSeverity: "moderate"},
		{ID: "CVE-1", Product: "p", RedHatSeverity: "critical", RedHatStatement: "s"},
	})
	if len(m) != 1 || m[0].RedHatSeverity != "critical" || m[0].RedHatStatement != "s" {
		t.Fatalf("%+v", m)
	}
}
