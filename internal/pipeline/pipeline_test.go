package pipeline

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/output"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/internal/triage"
)

type fakeSource struct {
	name string
	fs   []finding.Finding
	err  error

	mu    sync.Mutex
	since map[string]time.Time // by product: the window start it was last asked with
}

func (f *fakeSource) Name() string { return f.name }
func (f *fakeSource) Fetch(_ context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	f.mu.Lock()
	if f.since == nil {
		f.since = map[string]time.Time{}
	}
	f.since[sel.Product] = since
	f.mu.Unlock()
	var out []finding.Finding
	for _, x := range f.fs {
		if x.Product == sel.Product {
			out = append(out, x)
		}
	}
	return out, f.err
}

type fakeKEV struct{ listed map[string]bool }

func (k *fakeKEV) Name() string { return "kev" }
func (k *fakeKEV) Enrich(_ context.Context, fs []finding.Finding) error {
	for i := range fs {
		for _, id := range fs[i].CVEs() {
			if k.listed[id] {
				fs[i].KEV = true
			}
		}
	}
	return nil
}

type captureOutput struct {
	reports []report.Report
	err     error
}

func (c *captureOutput) Name() string { return "capture" }
func (c *captureOutput) Render(_ context.Context, r report.Report) error {
	c.reports = append(c.reports, r)
	return c.err
}

type env struct {
	cfg      *config.Config
	products []catalog.Product
	store    *state.Store
	out      *captureOutput
	kev      *fakeKEV
	src      []sources.Source
	now      time.Time
	dbPath   string
}

func setup(t *testing.T) *env {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{ConfigPaths: []string{"../../defaults/config.yaml"}, Paths: []string{"../../defaults/sources.yaml"}, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Run.RetryFailedAfter = config.Duration(time.Millisecond) // the default 3m would stall every failing source
	stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '26.x', exposure: internet}\n  argocd: '3.x'\n"))
	if err != nil {
		t.Fatal(err)
	}
	products, err := catalog.Resolve(cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	dbPath := filepath.Join(t.TempDir(), "s.db")
	store, err := state.Open(context.Background(), dbPath, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return &env{
		cfg: cfg, products: products, store: store, out: &captureOutput{}, kev: &fakeKEV{listed: map[string]bool{}},
		now: now, dbPath: dbPath,
		src: []sources.Source{
			&fakeSource{name: "ghsa", fs: []finding.Finding{
				{ID: "GHSA-kc-1", Aliases: []string{"CVE-2026-1"}, Product: "keycloak", Title: "kc vuln", CVSS: 8.1, Severity: "high",
					Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.1.4"}}, Fixed: []string{"26.1.4"}, Sources: []string{"ghsa"}, Modified: now},
				{ID: "GHSA-ac-low", Product: "argocd", Title: "low", CVSS: 2.0, Sources: []string{"ghsa"}, Modified: now},
			}},
			&fakeSource{name: "nvd", fs: []finding.Finding{
				{ID: "CVE-2026-1", Product: "keycloak", CVSS: 8.1, Sources: []string{"nvd"}, Modified: now},
				{ID: "CVE-2026-2", Product: "argocd", Title: "old line", CVSS: 9.0, Affected: []finding.Range{{Fixed: "2.9.0"}}, Sources: []string{"nvd"}, Modified: now},
			}},
			&fakeSource{name: "osv", err: errors.New("connection refused")},
		},
	}
}

func (e *env) run(t *testing.T, mut func(*Options)) (*report.Report, error) {
	t.Helper()
	o := Options{
		Config: e.cfg, Products: e.products, Sources: e.src, Enrichers: []sources.Enricher{e.kev},
		Store: e.store, Outputs: []output.Output{e.out},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return e.now },
	}
	if mut != nil {
		mut(&o)
	}
	return Run(context.Background(), o)
}

func TestRunEndToEnd(t *testing.T) {
	e := setup(t)

	// First run: one keycloak finding (merged from ghsa+nvd), one argocd
	// finding not affected; the low one is below min_cvss; osv fails.
	rep, err := e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total()+rep.NotRelevant != 2 || rep.BelowThreshold != 1 || len(rep.Warnings) != 2 {
		t.Fatalf("first run: total=%d notrel=%d below=%d warnings=%v", rep.Total(), rep.NotRelevant, rep.BelowThreshold, rep.Warnings)
	}
	if rep.NotRelevant != 1 {
		t.Fatalf("not_affected finding should collapse: %+v", rep)
	}
	kc := rep.Items()[0]
	if kc.ID != "CVE-2026-1" || kc.Match != "unknown" || kc.Change != "new" {
		t.Fatalf("keycloak item: %+v", kc)
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "osv/keycloak: connection refused") {
		t.Fatalf("warnings: %v", rep.Warnings)
	}
	byName := map[string]report.SourceStat{}
	for _, s := range rep.Sources {
		byName[s.Name] = s
	}
	if byName["ghsa"].Findings != 2 || byName["nvd"].Findings != 2 || byName["osv"].Errors != 2 || byName["kev"].Name == "" {
		t.Fatalf("source stats: %+v", rep.Sources)
	}
	if last, ok, _ := e.store.LastSuccess(context.Background()); !ok || !last.Equal(e.now) {
		t.Fatal("last success not stored")
	}

	// Second run: nothing new.
	e.now = e.now.Add(24 * time.Hour)
	rep, err = e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Empty() || rep.NotRelevant != 0 || rep.Unchanged != 2 {
		t.Fatalf("second run should be empty: total=%d unchanged=%d", rep.Total(), rep.Unchanged)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2026-1" || rep.Open[0].DaysOpen != 1 {
		t.Fatalf("keycloak finding must stay open, the not-affected argocd one not: %+v", rep.Open)
	}
	if rep.Since != e.now.Add(-48*time.Hour) {
		t.Fatalf("window should start at last success minus overlap: %v", rep.Since)
	}

	// Third run: the CVE is now KEV-listed and must be re-reported.
	e.now = e.now.Add(24 * time.Hour)
	e.kev.listed["CVE-2026-1"] = true
	rep, err = e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total() != 1 || !strings.Contains(rep.Items()[0].Change, "added to CISA KEV") || rep.Items()[0].Priority != "P1" {
		t.Fatalf("KEV re-report: %+v", rep.Items())
	}
	if len(rep.Open) != 0 {
		t.Fatalf("a finding reported in this run is not also listed as still open: %+v", rep.Open)
	}
}

type failingKEV struct{}

func (failingKEV) Name() string { return "kev" }
func (failingKEV) Enrich(context.Context, []finding.Finding) error {
	return errors.New("no KEV catalog")
}

func TestKEVFlagKeptWhileCatalogUnavailable(t *testing.T) {
	tests := []struct {
		name string
		kev  func(e *env) sources.Enricher // on the second run
	}{
		{"catalog available", func(e *env) sources.Enricher { return e.kev }},
		{"catalog unavailable", func(*env) sources.Enricher { return failingKEV{} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			e.src[2].(*fakeSource).err = nil
			e.kev.listed["CVE-2026-1"] = true
			if _, err := e.run(t, nil); err != nil {
				t.Fatal(err)
			}
			// A new fix while the catalog may be down: reported with its KEV flag.
			e.now = e.now.Add(24 * time.Hour)
			kc := &e.src[0].(*fakeSource).fs[0]
			kc.Fixed, kc.Modified = append(kc.Fixed, "26.2.0"), e.now
			rep, err := e.run(t, func(o *Options) { o.Enrichers = []sources.Enricher{tt.kev(e)} })
			if err != nil || rep.Total() != 1 {
				t.Fatalf("second run: %v %+v", err, rep.Items())
			}
			if it := rep.Items()[0]; !it.KEV || it.Priority != "P1" || strings.Contains(it.Change, "KEV") {
				t.Fatalf("KEV flag must be kept: %+v", it)
			}
			// The catalog is back: nothing changed, nothing reported.
			e.now = e.now.Add(24 * time.Hour)
			if rep, err = e.run(t, nil); err != nil || !rep.Empty() {
				t.Fatalf("no false \"added to CISA KEV\": %v %+v", err, rep.Items())
			}
		})
	}
}

// staleKEV applies an old cached catalog and reports the failed download,
// like kev.Enricher when only its cache is left.
type staleKEV struct{ fakeKEV }

func (k *staleKEV) Enrich(ctx context.Context, fs []finding.Finding) error {
	_ = k.fakeKEV.Enrich(ctx, fs)
	return errors.New("KEV download failed; used the cached catalog from 2026-09-12 (30d old)")
}

func TestStaleKEVCatalogIsASourceFailure(t *testing.T) {
	e := setup(t)
	stale := &staleKEV{fakeKEV{listed: map[string]bool{"CVE-2026-1": true}}}
	rep, err := e.run(t, func(o *Options) { o.Enrichers = []sources.Enricher{stale} })
	if err != nil || rep.Total() != 1 {
		t.Fatalf("%v %+v", err, rep.Items())
	}
	if it := rep.Items()[0]; !it.KEV || it.Priority != "P1" {
		t.Fatalf("the stale catalog must still be applied: %+v", it)
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "kev (enrichment): KEV download failed; used the cached catalog") {
		t.Fatalf("warnings: %v", rep.Warnings)
	}
	for _, s := range rep.Sources {
		if s.Name == "kev" && s.Errors != 1 {
			t.Fatalf("kev must count as failing: %+v", s)
		}
	}
}

func TestOpenFindingAddedToKEV(t *testing.T) {
	tests := []struct {
		name    string
		listed  string // CVE in the KEV catalog on the second run
		fetched bool   // the sources return the advisory again
		want    string // reported IDs
	}{
		{"open finding listed, not fetched", "CVE-2026-1", false, "CVE-2026-1"},
		{"open finding listed, fetched again", "CVE-2026-1", true, "CVE-2026-1"},
		{"nothing listed", "", false, ""},
		{"not-affected finding listed", "CVE-2026-2", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			e.src[2].(*fakeSource).err = nil
			if _, err := e.run(t, nil); err != nil {
				t.Fatal(err)
			}
			if !tt.fetched {
				e.src = nil // nothing modified within the window
			}
			e.now = e.now.Add(24 * time.Hour)
			e.kev.listed[tt.listed] = true
			rep, err := e.run(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, it := range rep.Items() {
				ids = append(ids, it.ID)
				if !it.KEV || it.Change != "added to CISA KEV" || it.Priority != "P1" {
					t.Fatalf("reported as a change and re-prioritised: %+v", it)
				}
			}
			if strings.Join(ids, ",") != tt.want {
				t.Fatalf("reported %v, want %q", ids, tt.want)
			}
			if len(rep.Open)+rep.Total() != 1 {
				t.Fatalf("the keycloak finding is either reported or still open: open=%+v", rep.Open)
			}
			// Next run: the stored flag is set, nothing is reported again.
			e.now = e.now.Add(24 * time.Hour)
			if rep, err = e.run(t, nil); err != nil || !rep.Empty() || len(rep.Open) != 1 || rep.Open[0].KEV != (tt.want != "") {
				t.Fatalf("third run: %v %+v open=%+v", err, rep.Items(), rep.Open)
			}
		})
	}
}

type fakeEPSS struct {
	scores map[string]float64
	err    error
}

func (*fakeEPSS) Name() string { return "epss" }
func (x *fakeEPSS) Enrich(_ context.Context, fs []finding.Finding) error {
	if x.err != nil {
		return x.err
	}
	for i := range fs {
		for _, id := range fs[i].CVEs() {
			if s, ok := x.scores[id]; ok && s > fs[i].EPSS {
				fs[i].EPSS = s
			}
		}
	}
	return nil
}

// epssEnv reports two keycloak findings (CVE-2026-1 and CVE-2026-5, both
// P3 by the rules) with EPSS 0.01 and returns the environment; later runs
// use runEPSS.
func epssEnv(t *testing.T) (*env, *fakeEPSS) {
	t.Helper()
	e := setup(t)
	e.src[2].(*fakeSource).err = nil
	ghsa := e.src[0].(*fakeSource)
	ghsa.fs[0].CVSS, ghsa.fs[0].Severity = 5.0, "medium"
	e.src[1].(*fakeSource).fs[0].CVSS = 5.0
	ghsa.fs = append(ghsa.fs, finding.Finding{
		ID: "CVE-2026-5", Product: "keycloak", Title: "second", CVSS: 5.0, Severity: "medium",
		Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.1.4"}}, Sources: []string{"ghsa"}, Modified: e.now,
	})
	ep := &fakeEPSS{scores: map[string]float64{"CVE-2026-1": 0.01, "CVE-2026-5": 0.01}}
	rep, err := runEPSS(t, e, ep, nil)
	if err != nil || rep.Total() != 2 {
		t.Fatalf("first run: %v %+v", err, rep.Items())
	}
	for _, it := range rep.Items() {
		if it.Priority != "P3" {
			t.Fatalf("first run priority: %+v", it)
		}
	}
	return e, ep
}

func runEPSS(t *testing.T, e *env, ep *fakeEPSS, mut func(*Options)) (*report.Report, error) {
	t.Helper()
	return e.run(t, func(o *Options) {
		o.Enrichers = []sources.Enricher{e.kev, ep}
		if mut != nil {
			mut(o)
		}
	})
}

func TestOpenFindingEPSSCrossesThreshold(t *testing.T) {
	tests := []struct {
		name      string
		first     float64 // stored with the first report
		now       float64 // EPSS in the second run
		fetched   bool    // the sources return the advisory again
		noDetail  bool    // the stored row predates details
		kevBefore bool    // KEV-listed when first reported
		kevNow    bool    // listed in the second run
		want      string  // reported IDs
		change    string
	}{
		{name: "not fetched, crosses", first: 0.01, now: 0.8, want: "CVE-2026-1", change: "EPSS rose to 80% (from 1%)"},
		{name: "not fetched, already above", first: 0.2, now: 0.9},
		{name: "not fetched, rises below the threshold", first: 0.01, now: 0.05},
		{name: "not fetched, falls", first: 0.2, now: 0.01},
		{name: "fetched again, crosses", first: 0.01, now: 0.8, fetched: true, want: "CVE-2026-1", change: "EPSS rose to 80% (from 1%)"},
		{name: "fetched again, already above", first: 0.2, now: 0.9, fetched: true},
		{name: "KEV-listed before, crosses", first: 0.01, now: 0.8, kevBefore: true},
		{name: "KEV-listed before, fetched again, crosses", first: 0.01, now: 0.8, kevBefore: true, fetched: true},
		{name: "KEV listing in the same run", first: 0.01, now: 0.8, kevNow: true, want: "CVE-2026-1", change: "added to CISA KEV"},
		{name: "no stored detail", first: 0.01, now: 0.8, noDetail: true},
		{name: "no stored detail, fetched again", first: 0.01, now: 0.8, noDetail: true, fetched: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			e.src[2].(*fakeSource).err = nil
			ghsa := e.src[0].(*fakeSource)
			ghsa.fs[0].CVSS, ghsa.fs[0].Severity = 5.0, "medium"
			e.src[1].(*fakeSource).fs[0].CVSS = 5.0
			ep := &fakeEPSS{scores: map[string]float64{"CVE-2026-1": tt.first}}
			e.kev.listed["CVE-2026-1"] = tt.kevBefore
			if rep, err := runEPSS(t, e, ep, nil); err != nil || rep.Total() != 1 || rep.Items()[0].Priority != "P3" && tt.first < triage.EPSSHigh && !tt.kevBefore {
				t.Fatalf("first run: %v %+v", err, rep.Items())
			}
			if tt.noDetail {
				db, err := sql.Open("sqlite", e.dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				if _, err := db.Exec(`UPDATE reported SET detail = NULL`); err != nil {
					t.Fatal(err)
				}
			}
			if !tt.fetched {
				e.src = nil
			}
			e.now = e.now.Add(24 * time.Hour)
			ep.scores["CVE-2026-1"] = tt.now
			e.kev.listed["CVE-2026-1"] = tt.kevBefore || tt.kevNow
			rep, err := runEPSS(t, e, ep, nil)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, it := range rep.Items() {
				ids = append(ids, it.ID)
				if it.Change != tt.change {
					t.Fatalf("change %q, want %q", it.Change, tt.change)
				}
				if tt.kevNow != (it.Priority == "P1") || (tt.change != "" && it.Priority > "P2") {
					t.Fatalf("priority: %+v", it)
				}
			}
			if strings.Join(ids, ",") != tt.want {
				t.Fatalf("reported %v, want %q", ids, tt.want)
			}
			if tt.fetched && rep.Unchanged != 2-len(ids) { // the argocd finding is always unchanged
				t.Fatalf("unchanged %d with %d reported", rep.Unchanged, len(ids))
			}
			// The crossing is reported once.
			e.now = e.now.Add(24 * time.Hour)
			if rep, err = runEPSS(t, e, ep, nil); err != nil || !rep.Empty() {
				t.Fatalf("third run: %v %+v", err, rep.Items())
			}
		})
	}
}

// The argocd finding is stored as not affected; its EPSS crossing is not
// reported, fetched again or not. The stack is the same in both runs, so
// the baseline is complete and the second run is a delta run.
func TestOpenFindingEPSSNotAffected(t *testing.T) {
	for _, fetched := range []bool{false, true} {
		t.Run(fmt.Sprintf("fetched=%v", fetched), func(t *testing.T) {
			e := setup(t)
			e.src[2].(*fakeSource).err = nil
			ep := &fakeEPSS{scores: map[string]float64{"CVE-2026-2": 0.01}}
			if _, err := runEPSS(t, e, ep, nil); err != nil {
				t.Fatal(err)
			}
			if !fetched {
				e.src = nil
			}
			e.now = e.now.Add(24 * time.Hour)
			ep.scores["CVE-2026-2"] = 0.8
			rep, err := runEPSS(t, e, ep, nil)
			if err != nil || !rep.Empty() {
				t.Fatalf("%v %+v", err, rep.Items())
			}
			if len(rep.Baselines) != 0 {
				t.Fatalf("the asserted run must not be a full-history check: %+v", rep.Baselines)
			}
		})
	}
}

func TestImageFindingEPSSCrossesThreshold(t *testing.T) {
	e := setup(t)
	e.cfg.Sources.Trivy = config.TrivySource{Enabled: true, MinSeverity: "critical", MinSeverityInternet: "high", MinEPSS: 0.1}
	trivy := &fakeImageSource{fakeSource: fakeSource{name: finding.SourceTrivy}}
	trivy.fs = []finding.Finding{imageFinding("CVE-2026-60", "keycloak", "high", 7.5, "1.1", e.now)}
	e.src = append(e.src[:2], trivy) // without the failing osv source, so the baselines complete
	ep := &fakeEPSS{scores: map[string]float64{"CVE-2026-60": 0.01}}
	if _, err := runEPSS(t, e, ep, nil); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(24 * time.Hour)
	ep.scores["CVE-2026-60"] = 0.8
	rep, err := runEPSS(t, e, ep, nil)
	if err != nil || rep.Total() != 1 {
		t.Fatalf("%v %+v", err, rep.Items())
	}
	if it := rep.Items()[0]; it.ID != "CVE-2026-60" || !it.ImageOnly || it.Change != "EPSS rose to 80% (from 1%)" {
		t.Fatalf("%+v", it)
	}
	if len(rep.Baselines) != 0 {
		t.Fatalf("the asserted run must not be a full-history check: %+v", rep.Baselines)
	}
}

func TestOpenFindingEPSSSourceFails(t *testing.T) {
	e, ep := epssEnv(t)
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	ep.scores["CVE-2026-1"], ep.err = 0.9, errors.New("epss unreachable")
	rep, err := runEPSS(t, e, ep, nil)
	if err != nil || !rep.Empty() {
		t.Fatalf("%v %+v", err, rep.Items())
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "epss (enrichment): epss unreachable") {
		t.Fatalf("warnings: %v", rep.Warnings)
	}
	recs, err := e.store.ListReported(context.Background())
	if err != nil || len(recs) != 3 {
		t.Fatalf("%v %+v", err, recs)
	}
	for _, r := range recs {
		if r.Product == "keycloak" && r.Detail.Finding.EPSS != 0.01 {
			t.Fatalf("stored EPSS lowered or changed: %+v", r.Detail.Finding)
		}
	}
}

// reportedWithNewFix reports the keycloak finding with EPSS 0.5, then
// returns it from the sources again with a new fixed version, which is
// reported in the next run whatever the EPSS does.
func reportedWithNewFix(t *testing.T) (*env, *fakeEPSS) {
	t.Helper()
	e := setup(t)
	e.src[2].(*fakeSource).err = nil
	ep := &fakeEPSS{scores: map[string]float64{"CVE-2026-1": 0.5}}
	if rep, err := runEPSS(t, e, ep, nil); err != nil || rep.Total() != 1 || rep.Items()[0].Priority != "P2" {
		t.Fatalf("first run: %v %+v", err, rep.Items())
	}
	e.now = e.now.Add(24 * time.Hour)
	kc := &e.src[0].(*fakeSource).fs[0]
	kc.Fixed, kc.Modified = append(kc.Fixed, "26.2.0"), e.now
	return e, ep
}

func storedEPSS(t *testing.T, e *env) float64 {
	t.Helper()
	recs, err := e.store.ListReported(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.ID == "CVE-2026-1" {
			return r.Detail.Finding.EPSS
		}
	}
	t.Fatal("CVE-2026-1 not stored")
	return 0
}

func TestEPSSCarriedWhileSourceFails(t *testing.T) {
	e, ep := reportedWithNewFix(t)
	ep.err = errors.New("epss unreachable")
	rep, err := runEPSS(t, e, ep, nil)
	if err != nil || rep.Total() != 1 {
		t.Fatalf("%v %+v", err, rep.Items())
	}
	if it := rep.Items()[0]; it.Change != "fixed version released: 26.2.0" || it.Priority != "P2" || it.EPSS != 0.5 {
		t.Fatalf("%+v", it)
	}
	if !strings.Contains(strings.Join(rep.Warnings, " "), "epss (enrichment): epss unreachable") {
		t.Fatalf("warnings: %v", rep.Warnings)
	}
	if got := storedEPSS(t, e); got != 0.5 {
		t.Fatalf("stored EPSS %v, want 0.5", got)
	}
	// EPSS is back: no rise to report.
	e.now = e.now.Add(24 * time.Hour)
	ep.err = nil
	if rep, err = runEPSS(t, e, ep, nil); err != nil || !rep.Empty() {
		t.Fatalf("third run: %v %+v", err, rep.Items())
	}
}

func TestEPSSNotCarriedWhenSourceHasNoScore(t *testing.T) {
	e, ep := reportedWithNewFix(t)
	ep.scores = map[string]float64{}
	if rep, err := runEPSS(t, e, ep, nil); err != nil || rep.Total() != 1 {
		t.Fatalf("%v %+v", err, rep.Items())
	}
	if got := storedEPSS(t, e); got != 0 {
		t.Fatalf("stored EPSS %v, want what the run had (0)", got)
	}
}

func TestOpenFindingsKEVAndEPSSTogether(t *testing.T) {
	e, ep := epssEnv(t)
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	e.kev.listed["CVE-2026-1"] = true
	ep.scores["CVE-2026-5"] = 0.8
	rep, err := runEPSS(t, e, ep, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range rep.Items() {
		got[it.ID] = it.Change
	}
	want := map[string]string{"CVE-2026-1": "added to CISA KEV", "CVE-2026-5": "EPSS rose to 80% (from 1%)"}
	if !maps.Equal(got, want) {
		t.Fatalf("reported %v, want %v", got, want)
	}
}

func TestEPSSChange(t *testing.T) {
	tests := []struct {
		from, to float64
		want     string
	}{
		{0.01, 0.82, "EPSS rose to 82% (from 1%)"},
		{0.004, 0.1, "EPSS rose to 10% (from <1%)"},
		{0, 1.0, "EPSS rose to 100% (from 0%)"},
		{0.096, 0.1, "EPSS rose to 10% (from 9%)"},
		{0.0999, 0.995, "EPSS rose to 99% (from 9%)"},
		{0.57, 1.0, "EPSS rose to 100% (from 57%)"},
		{0, 0, "EPSS rose to 0% (from 0%)"},
	}
	for _, tt := range tests {
		if got := epssChange(tt.from, tt.to); got != tt.want {
			t.Errorf("epssChange(%v, %v) = %q, want %q", tt.from, tt.to, got, tt.want)
		}
	}
}

func TestRejectedAdvisoryLeavesStillOpen(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.src[0].(*fakeSource).fs = append(e.src[0].(*fakeSource).fs, finding.Finding{
		ID: "GHSA-kc-2", Aliases: []string{"CVE-2026-3", "CVE-2026-4"}, Product: "keycloak", Title: "two CVEs", CVSS: 7.5,
		Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.1.4"}}, Sources: []string{"ghsa"}, Modified: e.now,
	})
	if _, err := e.run(t, nil); err != nil {
		t.Fatal(err)
	}
	e.src = nil // later runs fetch nothing new; the list comes from state only
	reject := func(ids ...string) {
		t.Helper()
		u, err := e.store.UpdateCVEList(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if err := u.Put(ctx, state.CVEListEntry{ID: id, Updated: e.now, Removed: true}); err != nil {
				t.Fatal(err)
			}
		}
		if err := u.Commit(ctx, state.CVEListMeta{}); err != nil {
			t.Fatal(err)
		}
	}
	openIDs := func() (string, string) {
		t.Helper()
		var logs strings.Builder
		e.now = e.now.Add(24 * time.Hour)
		rep, err := e.run(t, func(o *Options) {
			o.Log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: logx.LevelAudit}))
		})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, it := range rep.Open {
			ids = append(ids, it.ID)
		}
		return strings.Join(ids, ","), logs.String()
	}

	// One of two CVE IDs rejected: still open.
	reject("CVE-2026-4")
	if ids, _ := openIDs(); ids != "CVE-2026-1,CVE-2026-3" {
		t.Fatalf("open: %s", ids)
	}
	// Every CVE ID rejected: closed, with an audit line.
	reject("CVE-2026-3", "CVE-2026-1")
	ids, logs := openIDs()
	if ids != "" {
		t.Fatalf("rejected advisories must leave Still open: %s", ids)
	}
	if !strings.Contains(logs, `msg="advisory rejected"`) || !strings.Contains(logs, "id=CVE-2026-3") {
		t.Fatalf("audit: %s", logs)
	}
}

func TestStillOpenFollowsStack(t *testing.T) {
	e := setup(t)
	if _, err := e.run(t, nil); err != nil {
		t.Fatal(err)
	}
	e.src = nil // later runs fetch nothing new; the list comes from state only
	withVersion := func(v string) func(*Options) {
		return func(o *Options) {
			stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '" + v + "', exposure: internet}\n  argocd: '3.x'\n"))
			if err != nil {
				t.Fatal(err)
			}
			if o.Products, err = catalog.Resolve(e.cfg, stack); err != nil {
				t.Fatal(err)
			}
		}
	}
	tests := []struct {
		name    string
		mut     func(*Options)
		wantIDs string
		match   string
		prio    string
	}{
		{"exact affected version", withVersion("26.1.0"), "CVE-2026-1", "affected", "P2"},
		{"partial overlap", withVersion("26.x"), "CVE-2026-1", "unknown", "P2"},
		{"upgraded past the fix", withVersion("26.1.4"), "", "", ""},
		{"product removed from stack", func(o *Options) { o.Products = o.Products[:1] }, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep, err := e.run(t, tt.mut)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, it := range rep.Open {
				ids = append(ids, it.ID)
			}
			if strings.Join(ids, ",") != tt.wantIDs {
				t.Fatalf("open: %+v", rep.Open)
			}
			if tt.wantIDs != "" && (rep.Open[0].Match != tt.match || rep.Open[0].Priority != tt.prio) {
				t.Fatalf("open item: %+v", rep.Open[0])
			}
		})
	}
}

func TestRunOutputFailureKeepsState(t *testing.T) {
	e := setup(t)
	e.out.err = errors.New("slack down")
	if _, err := e.run(t, nil); err == nil {
		t.Fatal("output failure must fail the run")
	}
	if _, ok, _ := e.store.LastSuccess(context.Background()); ok {
		t.Fatal("last success must not be stored after an output failure")
	}
	e.out.err = nil
	rep, err := e.run(t, nil)
	if err != nil || rep.Total() != 1 {
		t.Fatalf("findings must be reported again after a failed run: %v %+v", err, rep)
	}
}

// A source that fails keeps its own window start; the run's window and the
// other sources move on, so one flaky feed (NVD's 503s) neither loses
// advisories nor marks every run incomplete.
func TestFailedSourceKeepsItsWindow(t *testing.T) {
	e := setup(t)
	ghsa, osv := e.src[0].(*fakeSource), e.src[2].(*fakeSource)
	osv.err = nil
	if _, err := e.run(t, nil); err != nil {
		t.Fatal(err)
	}
	overlap := e.cfg.Run.Overlap.D()
	first := e.now

	// Second run: osv fails. The run counts as successful, osv keeps the
	// window start it had.
	e.now = e.now.Add(24 * time.Hour)
	osv.err = errors.New("connection refused")
	rep, err := e.run(t, nil)
	if err != nil || len(rep.Baselines) != 0 || len(rep.Warnings) == 0 {
		t.Fatalf("second run: %v baselines=%+v warnings=%q", err, rep.Baselines, rep.Warnings)
	}
	if last, ok, _ := e.store.LastSuccess(context.Background()); !ok || !last.Equal(e.now) {
		t.Fatalf("last success %v, want %v", last, e.now)
	}
	ctx := context.Background()
	if w, err := e.store.SourceWindows(ctx); err != nil || len(w) != 1 || !w["osv"].Equal(first.Add(-overlap)) {
		t.Fatalf("source windows after the failure: %v %v", w, err)
	}

	// Third run: osv asks again from where it stopped, the others from the
	// second run; then osv has caught up.
	second := e.now
	e.now = e.now.Add(24 * time.Hour)
	osv.err = nil
	if _, err := e.run(t, nil); err != nil {
		t.Fatal(err)
	}
	if got := osv.since["keycloak"]; !got.Equal(first.Add(-overlap)) {
		t.Fatalf("osv asked from %v, want %v", got, first.Add(-overlap))
	}
	if got := ghsa.since["keycloak"]; !got.Equal(second.Add(-overlap)) {
		t.Fatalf("ghsa asked from %v, want %v", got, second.Add(-overlap))
	}
	if w, err := e.store.SourceWindows(ctx); err != nil || len(w) != 0 {
		t.Fatalf("osv caught up, its window is cleared: %v %v", w, err)
	}
}

func TestRunDryRunAndCancel(t *testing.T) {
	e := setup(t)
	rep, err := e.run(t, func(o *Options) { o.DryRun = true })
	if err != nil || rep.Mode != report.ModeDryRun {
		t.Fatal(err)
	}
	if _, ok, _ := e.store.LastSuccess(context.Background()); ok {
		t.Fatal("dry run wrote state")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = Run(ctx, Options{
		Config: e.cfg, Products: e.products, Sources: e.src, Store: e.store,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return e.now },
	})
	if err == nil {
		t.Fatal("cancelled run must fail")
	}
	if _, ok, _ := e.store.LastSuccess(context.Background()); ok {
		t.Fatal("cancelled run wrote state")
	}
}

func TestBootstrap(t *testing.T) {
	e := setup(t)
	rep, err := e.run(t, func(o *Options) { o.Bootstrap = true })
	if err != nil {
		t.Fatal(err)
	}
	if rep.Mode != report.ModeBootstrap || !rep.Empty() || len(rep.Baselines) != 2 || rep.Baselines[0].Reason != report.BaselineBootstrap {
		t.Fatalf("bootstrap: everything is history: %+v", rep)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2026-1" {
		t.Fatalf("what affects us is listed at once: %+v", rep.Open)
	}
	rep, err = e.run(t, nil)
	if err != nil || !rep.Empty() {
		t.Fatalf("after bootstrap nothing is new: %v %+v", err, rep)
	}
}

// history builds a stack with one product and old advisories (outside any
// window), so a full-history check finds them as history, not news.
func history(t *testing.T) *env {
	e := setup(t)
	old := e.now.AddDate(-1, 0, 0)
	e.src = []sources.Source{&fakeSource{name: "ghsa", fs: []finding.Finding{
		{ID: "CVE-2025-1", Product: "keycloak", Title: "affects 20.x", CVSS: 9.8, Severity: "critical",
			Affected: []finding.Range{{Introduced: "20.0.0", Fixed: "21.0.0"}}, Fixed: []string{"21.0.0"}, Sources: []string{"ghsa"}, Modified: old},
		{ID: "CVE-2025-2", Product: "keycloak", Title: "affects 26.x before 26.3", CVSS: 7.5, Severity: "high",
			Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.3.0"}}, Fixed: []string{"26.3.0"}, Sources: []string{"ghsa"}, Modified: old},
		{ID: "GITLAB-POST", Product: "keycloak", Title: "old post without versions", CVSS: 8.0, Severity: "high", Sources: []string{"ghsa"}, Modified: old},
	}}}
	return e
}

func stackWith(t *testing.T, e *env, keycloak string) func(*Options) {
	return func(o *Options) {
		stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '" + keycloak + "', exposure: internet}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if o.Products, err = catalog.Resolve(e.cfg, stack); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBaselineFindsOldVulnerabilities(t *testing.T) {
	e := history(t)

	// First run with an old version: nothing is "new", but the full history
	// shows what affects 20.0.3 right away.
	rep, err := e.run(t, stackWith(t, e, "20.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Empty() || len(rep.Baselines) != 1 {
		t.Fatalf("history is not news: total=%d baselines=%+v", rep.Total(), rep.Baselines)
	}
	b := rep.Baselines[0]
	if b.Product != "keycloak" || b.Reason != report.BaselineNew || b.Checked != 3 || b.Affected != 1 || b.Unknown != 0 || b.NoData != 1 || !b.Complete {
		t.Fatalf("baseline summary: %+v", b)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2025-1" || rep.Open[0].Priority != "P1" || rep.OpenUnknown != 1 {
		t.Fatalf("open after baseline: %+v unknown=%d", rep.Open, rep.OpenUnknown)
	}

	// Same version next day: no new check, the finding stays open from state.
	e.now = e.now.Add(24 * time.Hour)
	rep, err = e.run(t, stackWith(t, e, "20.0.3"))
	if err != nil || len(rep.Baselines) != 0 || len(rep.Open) != 1 || rep.Open[0].DaysOpen != 1 {
		t.Fatalf("second run: %v baselines=%+v open=%+v", err, rep.Baselines, rep.Open)
	}

	// Version change: checked again; the old one clears, the one for 26.x
	// before 26.3 now affects us. Still nothing reported as new.
	e.now = e.now.Add(24 * time.Hour)
	rep, err = e.run(t, stackWith(t, e, "26.1.0"))
	if err != nil || !rep.Empty() || len(rep.Baselines) != 1 || rep.Baselines[0].Reason != report.BaselineVersionChanged {
		t.Fatalf("version change: %v total=%d baselines=%+v", err, rep.Total(), rep.Baselines)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2025-2" {
		t.Fatalf("open after upgrade: %+v", rep.Open)
	}
}

// A release that reads advisories differently bumps matchingVersion: the
// daily window never fetches old advisories again, so only the re-check it
// triggers rewrites what was stored with the old reading.
func TestMatchingUpdateRereadsStoredFindings(t *testing.T) {
	e := history(t)
	src := e.src[0].(*fakeSource)
	// The old reading: 26.x before 27.0 instead of before 26.1.
	src.fs[1].Affected = []finding.Range{{Introduced: "26.0.0", Fixed: "27.0.0"}}
	rep, err := e.run(t, stackWith(t, e, "26.1.0"))
	if err != nil || len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2025-2" {
		t.Fatalf("first run: %v open=%+v", err, rep.Open)
	}
	// The baseline as an earlier release wrote it.
	var o Options
	stackWith(t, e, "26.1.0")(&o)
	p := o.Products[0]
	old := state.Baseline{Product: p.Key(), Constraint: p.Constraint.String(), Fingerprint: fingerprintAt(p, false, matchingVersion-1)}
	if err := e.store.Commit(context.Background(), e.now, nil, []state.Baseline{old}, false); err != nil {
		t.Fatal(err)
	}

	src.fs[1].Affected = []finding.Range{{Introduced: "26.0.0", Fixed: "26.1.0"}}
	e.now = e.now.Add(24 * time.Hour)
	rep, err = e.run(t, stackWith(t, e, "26.1.0"))
	if err != nil || !rep.Empty() || len(rep.Baselines) != 1 || rep.Baselines[0].Reason != report.BaselineMatching {
		t.Fatalf("re-check: %v total=%d baselines=%+v", err, rep.Total(), rep.Baselines)
	}
	if len(rep.Open) != 0 {
		t.Fatalf("stale reading still open: %+v", rep.Open)
	}
	// Once only.
	e.now = e.now.Add(24 * time.Hour)
	if rep, err = e.run(t, stackWith(t, e, "26.1.0")); err != nil || len(rep.Baselines) != 0 {
		t.Fatalf("third run: %v baselines=%+v", err, rep.Baselines)
	}
}

func TestBaselineOfRemovedProduct(t *testing.T) {
	tests := []struct {
		name       string
		wholeStack bool
		want       string // baseline reason when keycloak is back
	}{
		{"whole stack forgets it", true, report.BaselineNew},
		{"--product keeps it", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := history(t)
			if _, err := e.run(t, stackWith(t, e, "20.0.3")); err != nil {
				t.Fatal(err)
			}
			// keycloak removed from the stack, added again the next day.
			e.now = e.now.Add(24 * time.Hour)
			if _, err := e.run(t, func(o *Options) {
				stack, err := config.ParseStack([]byte("products:\n  argocd: {version: '3.1.0'}\n"))
				if err != nil {
					t.Fatal(err)
				}
				if o.Products, err = catalog.Resolve(e.cfg, stack); err != nil {
					t.Fatal(err)
				}
				o.WholeStack = tt.wholeStack
			}); err != nil {
				t.Fatal(err)
			}
			e.now = e.now.Add(24 * time.Hour)
			rep, err := e.run(t, stackWith(t, e, "20.0.3"))
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, b := range rep.Baselines {
				if b.Product == "keycloak" {
					got = b.Reason
				}
			}
			if got != tt.want {
				t.Fatalf("baseline reason %q, want %q (%+v)", got, tt.want, rep.Baselines)
			}
		})
	}
}

func TestBaselineRetriedAfterSourceFailure(t *testing.T) {
	e := history(t)
	e.src = append(e.src, &fakeSource{name: "osv", err: errors.New("connection refused")})
	rep, err := e.run(t, stackWith(t, e, "20.0.3"))
	if err != nil || len(rep.Baselines) != 1 || rep.Baselines[0].Complete {
		t.Fatalf("incomplete baseline: %v %+v", err, rep.Baselines)
	}
	e.now = e.now.Add(24 * time.Hour)
	e.src = e.src[:1]
	rep, err = e.run(t, stackWith(t, e, "20.0.3"))
	if err != nil || len(rep.Baselines) != 1 || !rep.Baselines[0].Complete {
		t.Fatalf("the check must be repeated until complete: %v %+v", err, rep.Baselines)
	}
	e.now = e.now.Add(24 * time.Hour)
	if rep, err = e.run(t, stackWith(t, e, "20.0.3")); err != nil || len(rep.Baselines) != 0 {
		t.Fatalf("complete now: %v %+v", err, rep.Baselines)
	}
}

func TestBaselineKeepsRecentChanges(t *testing.T) {
	e := history(t)
	if _, err := e.run(t, stackWith(t, e, "20.0.3")); err != nil {
		t.Fatal(err)
	}
	// The old advisory is added to KEV today (modified now) while the
	// version changes: it must be reported as updated, not filed as history.
	e.now = e.now.Add(24 * time.Hour)
	f := &e.src[0].(*fakeSource).fs[0]
	f.Modified = e.now
	e.kev.listed["CVE-2025-1"] = true
	rep, err := e.run(t, stackWith(t, e, "20.0.4"))
	if err != nil || rep.Total() != 1 || !strings.Contains(rep.Items()[0].Change, "KEV") {
		t.Fatalf("recent change on a re-checked product: %v %+v", err, rep.Items())
	}
}

func TestStillOpenWithoutVersionData(t *testing.T) {
	e := setup(t)
	// A GitLab-style advisory: no affected versions at all.
	e.src = []sources.Source{&fakeSource{name: "rss", fs: []finding.Finding{
		{ID: "CVE-2026-9", Product: "keycloak", Title: "no version data", CVSS: 9.1, Severity: "critical", Sources: []string{"rss"}, Modified: e.now},
	}}}
	if _, err := e.run(t, nil); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	withVersion := func(v string) func(*Options) {
		return func(o *Options) {
			stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '" + v + "', exposure: internet}\n"))
			if err != nil {
				t.Fatal(err)
			}
			if o.Products, err = catalog.Resolve(e.cfg, stack); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Critical and internet-facing, but without version data it may not
	// affect us: P2, not P1.
	rep, err := e.run(t, withVersion("26.x"))
	if err != nil || len(rep.Open) != 1 || !rep.Open[0].NoVersionData || rep.Open[0].Priority != "P2" {
		t.Fatalf("same version: must stay open with its priority: %v %+v", err, rep.Open)
	}
	rep, err = e.run(t, withVersion("27.0.0"))
	if err != nil || len(rep.Open) != 0 || rep.OpenUnknown != 1 {
		t.Fatalf("after an upgrade it is only counted: %v open=%+v unknown=%d", err, rep.Open, rep.OpenUnknown)
	}
}

func TestAudit(t *testing.T) {
	e := history(t)
	e.src = append(e.src, &fakeSource{name: "osv", err: errors.New("connection refused")})
	stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '26.x', exposure: internet}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := catalog.Resolve(e.cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	links := report.AdvisoryLinks{NVD: "https://nvd.example/{id}", GitHub: "https://gh.example/{id}"}
	res, warnings, err := Audit(context.Background(), e.src, []sources.Enricher{e.kev}, ps, links, config.OSSource{}, 4, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || len(res) != 1 || len(warnings) != 1 {
		t.Fatalf("audit: %v %+v %v", err, res, warnings)
	}
	r := res[0]
	// 26.x vs "26.0.0-26.3.0": depends on the exact version; "20.x" is not
	// affected; the post without versions is only counted.
	if r.Checked != 3 || r.Affected != 0 || r.Unknown != 1 || r.NotAffected != 1 || r.NoVersionData != 1 || r.Complete {
		t.Fatalf("counts: %+v", r)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "CVE-2025-2" || r.Findings[0].Fixed[0] != "26.3.0" {
		t.Fatalf("findings: %+v", r.Findings)
	}
	if adv := r.Findings[0].Advisories; len(adv) != 1 || adv[0].URL != "https://nvd.example/CVE-2025-2" {
		t.Fatalf("advisory links: %+v", adv)
	}
	if n, _ := e.store.Baselines(context.Background()); len(n) != 0 {
		t.Fatal("audit must not write state")
	}
}

func TestAuditPerVersion(t *testing.T) {
	e := history(t)
	stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '20.0.3 || 26.1.0'}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := catalog.Resolve(e.cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := Audit(context.Background(), e.src, nil, ps, report.AdvisoryLinks{}, config.OSSource{}, 4, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r := res[0]
	if len(r.ByVersion) != 2 || r.ByVersion[0] != (VersionCount{"20.0.3", 1, 0}) || r.ByVersion[1] != (VersionCount{"26.1.0", 1, 0}) {
		t.Fatalf("by version: %+v", r.ByVersion)
	}
	got := map[string]string{}
	for _, f := range r.Findings {
		got[f.ID] = strings.Join(f.Versions, ",")
	}
	if got["CVE-2025-1"] != "20.0.3" || got["CVE-2025-2"] != "26.1.0" {
		t.Fatalf("which version each finding affects: %v", got)
	}
}

type fakeImageSource struct {
	fakeSource
	unmatched []string
}

func (f *fakeImageSource) UnmatchedImages() []string { return f.unmatched }

func imageFinding(id, product, sev string, cvss float64, fixed string, now time.Time) finding.Finding {
	return finding.Finding{ID: id, Product: product, Title: "pkg " + id, Severity: sev, CVSS: cvss, Sources: []string{finding.SourceTrivy}, Modified: now,
		Packages: []finding.Package{{Image: "quay.io/x/" + product + ":1", Name: "libfoo", Type: "deb", Installed: "1.0", Fixed: fixed}}}
}

func TestImageFindings(t *testing.T) {
	e := setup(t)
	e.cfg.Sources.Trivy = config.TrivySource{Enabled: true, MinSeverity: "critical", MinSeverityInternet: "high", MinEPSS: 0.1}
	trivy := &fakeImageSource{fakeSource: fakeSource{name: finding.SourceTrivy}, unmatched: []string{"docker.io/library/redis:8"}}
	trivy.fs = []finding.Finding{
		imageFinding("CVE-2026-50", "keycloak", "high", 7.5, "1.1", e.now), // internet-facing: high is enough
		imageFinding("CVE-2026-51", "argocd", "high", 7.5, "1.1", e.now),   // internal: needs critical, filtered
		imageFinding("CVE-2026-52", "argocd", "critical", 9.8, "", e.now),  // no fixed package, filtered
		imageFinding("CVE-2026-1", "keycloak", "high", 8.1, "1.1", e.now),  // the ghsa advisory too: confirmed
	}
	e.src = append(e.src[:2], trivy) // without the failing osv source, so the baselines complete

	// First run: both products are new, so image-only findings are history,
	// listed as still open; the confirmed one is reported (recent advisory).
	rep, err := e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ImageFiltered != 2 || len(rep.UnmatchedImages) != 1 {
		t.Fatalf("filtered=%d unmatched=%v", rep.ImageFiltered, rep.UnmatchedImages)
	}
	kc := rep.Items()[0]
	if kc.ID != "CVE-2026-1" || kc.Match != "affected" || kc.ImageOnly || len(kc.Packages) != 1 {
		t.Fatalf("confirmed finding: %+v", kc)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2026-50" || !rep.Open[0].ImageOnly || len(rep.Open[0].Packages) != 1 {
		t.Fatalf("image-only history must be listed as still open: %+v", rep.Open)
	}

	// Second run: a new image finding is reported; CVE-2026-50 is gone from
	// the images, so it is no longer open.
	e.now = e.now.Add(24 * time.Hour)
	trivy.fs = []finding.Finding{
		imageFinding("CVE-2026-53", "keycloak", "critical", 9.8, "2.0", e.now),
		imageFinding("CVE-2026-1", "keycloak", "high", 8.1, "1.1", e.now),
	}
	rep, err = e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total() != 1 || rep.Items()[0].ID != "CVE-2026-53" || !rep.Items()[0].ImageOnly || rep.Items()[0].Match != "affected" {
		t.Fatalf("new image finding: %+v", rep.Items())
	}
	if !strings.Contains(rep.Items()[0].Action, "libfoo 2.0") {
		t.Fatalf("image-only action should name the package fix: %q", rep.Items()[0].Action)
	}
	for _, it := range rep.Open {
		if it.ID == "CVE-2026-50" {
			t.Fatalf("CVE-2026-50 left the images and must clear: %+v", rep.Open)
		}
	}

	// Third run: Trivy fails; image findings stay open as they were.
	e.now = e.now.Add(24 * time.Hour)
	trivy.err = errors.New("forbidden")
	rep, err = e.run(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, it := range rep.Open {
		ids = append(ids, it.ID)
	}
	if !strings.Contains(strings.Join(ids, " "), "CVE-2026-53") {
		t.Fatalf("image findings must stay open while Trivy is down: %v", ids)
	}
}

func TestKeepImageFinding(t *testing.T) {
	cfg := config.TrivySource{MinSeverity: "critical", MinSeverityInternet: "high", MinEPSS: 0.1}
	internal := catalog.Product{Exposure: "internal"}
	f := imageFinding("CVE-1", "p", "medium", 5, "1.1", time.Time{})
	if keepImageFinding(f, internal, cfg) {
		t.Error("medium without KEV/EPSS must be filtered")
	}
	f.EPSS = 0.2
	if !keepImageFinding(f, internal, cfg) {
		t.Error("EPSS above min_epss keeps it")
	}
	f.EPSS, f.KEV = 0, true
	if !keepImageFinding(f, internal, cfg) {
		t.Error("KEV keeps it")
	}
	f.Packages[0].Fixed = ""
	if keepImageFinding(f, internal, cfg) {
		t.Error("no fixed package: never kept")
	}
}

func TestMatchNoteExplainsMissingVersionData(t *testing.T) {
	e := setup(t)
	byName := map[string]catalog.Product{}
	for _, p := range e.products {
		byName[p.Key()] = p
	}
	note := "advisory covers several packages (server, ui); can't tell which one we run"
	fs := []finding.Finding{
		{ID: "GHSA-a", Product: "keycloak", MatchNote: note},
		{ID: "GHSA-b", Product: "keycloak", MatchNote: note, Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "27.0.0", Source: "osv"}}},
	}
	MatchAll(fs, byName)
	if fs[0].Match != "unknown" || fs[0].MatchDetail != note {
		t.Fatalf("no version data: %s %q", fs[0].Match, fs[0].MatchDetail)
	}
	if fs[1].Match != "affected" || fs[1].MatchDetail == note {
		t.Fatalf("another source's version data decides: %s %q", fs[1].Match, fs[1].MatchDetail)
	}
}

func TestFilterKernel(t *testing.T) {
	k := func(id string, kev bool, epss float64) finding.Finding {
		return finding.Finding{ID: id, Product: "debian-13-kernel", Sources: []string{"os"}, KEV: kev, EPSS: epss}
	}
	fs := []finding.Finding{k("CVE-1", true, 0), k("CVE-2", false, 0.3), k("CVE-3", false, 0.01),
		{ID: "CVE-4", Product: "debian-13-kernel", Sources: []string{"os", "nvd"}}}
	got, n := filterKernel(fs, config.OSSource{MinEPSS: 0.1})
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, " ") != "CVE-1 CVE-2 CVE-4" || n != 1 {
		t.Fatalf("kept %v, filtered %d", ids, n)
	}
}

type explainCompleter struct{ prompts []string }

func (c *explainCompleter) Complete(_ context.Context, _, user string, _ map[string]any) (string, error) {
	c.prompts = append(c.prompts, user)
	return `{"results":[{"key":"f1","relevant":"yes","priority":"P1","summary":"An attacker on the internet can take over admin accounts.","reasoning":"Internet-facing and critical.","action":"Upgrade Keycloak to 21.0.0 today."}]}`, nil
}

func TestHistoryP1GetsExplained(t *testing.T) {
	e := history(t)
	c := &explainCompleter{}
	withTriage := func(o *Options) {
		stackWith(t, e, "20.0.3")(o)
		cfg := e.cfg.Triage
		cfg.Enabled = true
		o.Triager = triage.New(cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	rep, err := e.run(t, withTriage)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.prompts) != 1 || !strings.Contains(c.prompts[0], "CVE-2025-1") || strings.Contains(c.prompts[0], "CVE-2025-2") {
		t.Fatalf("only the first-seen P1 history goes to Claude: %q", c.prompts)
	}
	if len(rep.Open) != 1 || rep.Open[0].Summary != "An attacker on the internet can take over admin accounts." || rep.Open[0].Action != "Upgrade Keycloak to 21.0.0 today." || !rep.Open[0].FirstSeen {
		t.Fatalf("open item: %+v", rep.Open)
	}

	// Next day: the explanation comes from state, Claude isn't asked again.
	e.now = e.now.Add(24 * time.Hour)
	rep, err = e.run(t, withTriage)
	if err != nil || len(c.prompts) != 1 || len(rep.Open) != 1 || rep.Open[0].Summary == "" || rep.Open[0].FirstSeen {
		t.Fatalf("second run: %v prompts=%d open=%+v", err, len(c.prompts), rep.Open)
	}
}

// flakySource fails its first n fetches of keycloak, like NVD in a short
// outage.
type flakySource struct {
	fakeSource
	n int
}

func (f *flakySource) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	if sel.Product == "keycloak" && f.n > 0 { // one fetch of keycloak at a time: no race on n
		f.n--
		return nil, errors.New("HTTP 503: 503 Service Unavailable")
	}
	return f.fakeSource.Fetch(ctx, sel, since)
}

func TestFailedSourceAskedAgain(t *testing.T) {
	tests := []struct {
		name     string
		failures int
		wait     time.Duration
		complete bool
	}{
		{"recovers", 1, time.Millisecond, true},
		{"fails again", 2, time.Millisecond, false},
		{"retry off", 1, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			e.cfg.Run.RetryFailedAfter = config.Duration(tt.wait)
			src := &flakySource{fakeSource: fakeSource{name: "nvd"}}
			e.src = []sources.Source{src}
			if _, err := e.run(t, nil); err != nil { // baselines: the next run is a daily one
				t.Fatal(err)
			}
			e.now = e.now.Add(24 * time.Hour)
			src.fs = []finding.Finding{{ID: "CVE-2026-1", Product: "keycloak", Title: "new", CVSS: 7.5, Severity: "high",
				Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.9.0"}}, Sources: []string{"nvd"}, Modified: e.now}}
			src.n = tt.failures
			rep, err := e.run(t, nil)
			if err != nil {
				t.Fatal(err)
			}
			behind, err := e.store.SourceWindows(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if complete := len(behind) == 0; complete != tt.complete || (len(rep.Warnings) == 0) != tt.complete {
				t.Fatalf("complete=%v warnings=%q, want complete=%v", complete, rep.Warnings, tt.complete)
			}
			if tt.complete && rep.Total() != 1 {
				t.Fatalf("the finding of the second attempt is reported: total=%d", rep.Total())
			}
		})
	}
}
