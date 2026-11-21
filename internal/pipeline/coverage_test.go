package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/sources"
)

// failingFor fails for one product only.
type failingFor struct {
	sources.Source
	product string
}

func (f failingFor) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	if sel.Product == f.product {
		return nil, errors.New("timeout")
	}
	return f.Source.Fetch(ctx, sel, since)
}

// Ranges are tagged with their source, each source is matched on its own,
// and the findings only cvelist or only NVD found are counted.
func TestPerSourceMatchAndCoverage(t *testing.T) {
	e := setup(t)
	kc := func(id, src string, affected ...finding.Range) finding.Finding {
		return finding.Finding{ID: id, Product: "keycloak", CVSS: 8.1, Affected: affected, Sources: []string{src}, Modified: e.now}
	}
	nvdKC := kc("CVE-2026-1", "nvd", finding.Range{Fixed: "26.1.4"})
	nvdKC.AffectedVersions = []string{"26.0.1"}
	e.src = []sources.Source{
		&fakeSource{name: "ghsa", fs: []finding.Finding{kc("CVE-2026-1", "ghsa", finding.Range{Introduced: "26.0.0", Fixed: "27.0.0"})}},
		failingFor{&fakeSource{name: "nvd", fs: []finding.Finding{nvdKC, kc("CVE-2026-4", "nvd")}}, "argocd"},
		&fakeSource{name: sourceCVEList, fs: []finding.Finding{
			kc("CVE-2026-1", sourceCVEList, finding.Range{Introduced: "26.0.0", Fixed: "26.1.4"}),
			kc("CVE-2026-3", sourceCVEList),
			{ID: "CVE-2026-5", Product: "argocd", Sources: []string{sourceCVEList}, Modified: e.now},
		}},
	}
	stack, err := config.ParseStack([]byte("products:\n  keycloak: '26.1.4'\n  argocd: '3.x'\n"))
	if err != nil {
		t.Fatal(err)
	}
	products, err := catalog.Resolve(e.cfg, stack)
	if err != nil {
		t.Fatal(err)
	}

	col, err := Collect(context.Background(), e.src, products, time.Time{}, 4, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(col.Findings, func(f finding.Finding) bool { return f.ID == "CVE-2026-1" && f.Sources[0] == "nvd" })
	want := []finding.Range{{Fixed: "26.1.4", Source: "nvd"}, {Introduced: "26.0.1", LastAffected: "26.0.1", Exact: true, Source: "nvd"}}
	if i < 0 || !slices.Equal(col.Findings[i].Affected, want) || col.Findings[i].AffectedVersions != nil {
		t.Fatalf("tagged after fetch: %+v", col.Findings)
	}

	rep, err := e.run(t, func(o *Options) { o.Products = products })
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]int{sourceCVEList: 1, "nvd": 1}; !maps.Equal(rep.SingleSource, want) {
		t.Fatalf("single source: %v, want %v (argocd skipped: NVD failed for it)", rep.SingleSource, want)
	}
	// The tags are stored, so the open findings are re-matched per source.
	fs := []finding.Finding{detailOf(t, e, "keycloak", "CVE-2026-1").Finding}
	if fs[0].Match != "unknown" {
		t.Fatalf("stored match: %s", fs[0].Match)
	}
	MatchAll(fs, map[string]catalog.Product{"keycloak": products[slices.IndexFunc(products, func(p catalog.Product) bool { return p.Name == "keycloak" })]})
	if wantD := "sources disagree: cvelist: not affected; ghsa: affected (>=26.0.0 <27.0.0); nvd: not affected"; fs[0].Match != "unknown" || fs[0].MatchDetail != wantD {
		t.Fatalf("match: %s (%s), want unknown (%s)", fs[0].Match, fs[0].MatchDetail, wantD)
	}

	// Without the cvelist source nothing is counted.
	e.src = e.src[:2]
	e.now = e.now.Add(24 * time.Hour)
	if rep, err = e.run(t, func(o *Options) { o.Products = products }); err != nil || rep.SingleSource != nil {
		t.Fatalf("cvelist not running: %v %v", err, rep.SingleSource)
	}
}
