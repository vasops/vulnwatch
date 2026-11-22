package report_test

import (
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestBuild(t *testing.T) {
	r := reporttest.Sample()
	if r.NotRelevant != 1 || r.Total() != 2 || r.Empty() {
		t.Fatalf("counts: not_relevant=%d total=%d", r.NotRelevant, r.Total())
	}
	if len(r.Groups) != 2 || r.Groups[0].Priority != "P1" || r.Groups[1].Priority != "P3" {
		t.Fatalf("groups: %+v", r.Groups)
	}
	items := r.Items()
	if items[0].Change != "new" || items[1].Change == "new" || items[1].Triaged {
		t.Fatalf("items: %+v", items)
	}
	if !reporttest.Empty().Empty() {
		t.Fatal("empty report not empty")
	}
}

func TestFailedSources(t *testing.T) {
	r := report.Report{Warnings: []string{"osv/keycloak: timeout", "nvd/keycloak: HTTP 503", "osv/argocd: timeout", "kev (enrichment): refused"}}
	if got := strings.Join(r.FailedSources(), ","); got != "kev,nvd,osv" {
		t.Fatal(got)
	}
	if got := (report.Report{}).FailedSources(); got != nil {
		t.Fatal(got)
	}
}

func TestCurrentOpenCounts(t *testing.T) {
	// Sample: new P1 + updated P3 listed, P1 + P3 still open.
	got := map[string]int{}
	for _, c := range reporttest.Sample().CurrentOpenCounts() {
		got[c.Priority] = c.Count
	}
	if got["P1"] != 2 || got["P2"] != 0 || got["P3"] != 2 || got["P4"] != 0 {
		t.Fatalf("counts: %v", got)
	}
}
