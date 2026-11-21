// Package pipeline runs the vulnwatch stages: collect, normalize, dedup,
// enrich, match, filter against state, triage, report, persist.
package pipeline

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/output"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/safe"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/sources/cvelist"
	"github.com/vasops/vulnwatch/internal/sources/epss"
	"github.com/vasops/vulnwatch/internal/sources/ghsa"
	"github.com/vasops/vulnwatch/internal/sources/k8sfeed"
	"github.com/vasops/vulnwatch/internal/sources/kev"
	"github.com/vasops/vulnwatch/internal/sources/nvd"
	"github.com/vasops/vulnwatch/internal/sources/ostracker"
	"github.com/vasops/vulnwatch/internal/sources/osv"
	"github.com/vasops/vulnwatch/internal/sources/redhat"
	"github.com/vasops/vulnwatch/internal/sources/rss"
	"github.com/vasops/vulnwatch/internal/sources/trivy"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/internal/triage"
)

// BuildSources instantiates every enabled source and enricher from config.
// store (nil: none) holds the KEV cache and the cvelist index; release the
// sources with CloseSources after the run.
func BuildSources(cfg *config.Config, client *httpx.Client, getenv func(string) string, store *state.Store, log *slog.Logger) ([]sources.Source, []sources.Enricher) {
	var (
		cache sources.Cache
		index cvelist.Index
	)
	if store != nil {
		cache, index = store, store
	}
	s := cfg.Sources
	var srcs []sources.Source
	if s.GHSA.Enabled {
		srcs = append(srcs, ghsa.New(s.GHSA, client, getenv, log))
	}
	if s.OSV.Enabled {
		srcs = append(srcs, osv.New(s.OSV, client))
	}
	if s.NVD.Enabled {
		srcs = append(srcs, nvd.New(s.NVD, client.WithTimeout(s.NVD.Timeout.D()), getenv))
	}
	if s.CVEList.Enabled {
		srcs = append(srcs, cvelist.New(s.CVEList, client, getenv, index, log))
	}
	if s.K8sFeed.Enabled {
		srcs = append(srcs, k8sfeed.New(s.K8sFeed, client))
	}
	if s.RSS.Enabled {
		srcs = append(srcs, rss.New(client))
	}
	if s.Trivy.Enabled {
		srcs = append(srcs, trivy.New(cfg, log))
	}
	if s.OS.Enabled {
		srcs = append(srcs, ostracker.New(s.OSV.BaseURL, client))
	}
	var enr []sources.Enricher
	if s.KEV.Enabled {
		enr = append(enr, kev.New(s.KEV, client, cache, log))
	}
	if s.EPSS.Enabled {
		enr = append(enr, epss.New(s.EPSS, client))
	}
	// After KEV and EPSS: they decide which statements are fetched first.
	if s.RedHat.Enabled {
		enr = append(enr, redhat.New(s.RedHat, client))
	}
	return srcs, enr
}

// CloseSources releases what the sources hold for a run (cvelist: its
// downloaded archives).
func CloseSources(srcs []sources.Source, log *slog.Logger) {
	for _, src := range srcs {
		if c, ok := src.(io.Closer); ok {
			if err := c.Close(); err != nil {
				log.Warn("source cleanup failed", "source", src.Name(), "err", err)
			}
		}
	}
}

// Collected is the result of Collect.
type Collected struct {
	Findings []finding.Finding // per product: Product is its Key()
	Raw      []finding.Finding // as the sources returned them, once per fetch (source stats)
	Warnings []string          // "<source>/<product>: <error>", sorted
	Failed   map[string]bool   // product keys with at least one failed source

	failures []failedFetch // what RetryFailed asks again
}

// failedFetch is one source that failed for one fetch unit.
type failedFetch struct {
	src   sources.Source
	unit  *fetchUnit
	since time.Time
}

// fetchUnit is one product fetched once for every scope that runs it: the
// sources are asked per product, never per tenant.
type fetchUnit struct {
	sel      sources.Selector
	products []catalog.Product
	local    bool // the local stack runs it (in-cluster sources apply)
}

// fetchUnits groups the products by what the sources are asked: the
// catalog name, and for a kernel the package (versions are merged).
func fetchUnits(products []catalog.Product) []*fetchUnit {
	idx := map[string]*fetchUnit{}
	var out []*fetchUnit
	for _, p := range products {
		k := p.Name
		if p.OS != nil {
			k += "\x00" + p.OS.KernelPackage
		}
		u := idx[k]
		if u == nil {
			u = &fetchUnit{sel: selector(p)}
			idx[k] = u
			out = append(out, u)
		} else {
			for _, v := range selector(p).Versions {
				if !slices.Contains(u.sel.Versions, v) {
					u.sel.Versions = append(u.sel.Versions, v)
				}
			}
		}
		u.products = append(u.products, p)
		u.local = u.local || !p.Scope.Remote
	}
	return out
}

// Collect fetches from every source for every product in parallel (bounded),
// once per product however many tenants run it, and hands each scope its
// copy. In-cluster sources (Trivy) only serve the local stack. A zero since
// fetches the full history. Source failures become warnings; only context
// cancellation is an error.
func Collect(ctx context.Context, srcs []sources.Source, products []catalog.Product, since time.Time, concurrency int, log *slog.Logger) (Collected, error) {
	return CollectFrom(ctx, srcs, products, func(string) time.Time { return since }, concurrency, log)
}

// CollectFrom is Collect with a window start per source (by name): a
// source that failed in an earlier run asks again from where it stopped.
func CollectFrom(ctx context.Context, srcs []sources.Source, products []catalog.Product, sinceFor func(source string) time.Time, concurrency int, log *slog.Logger) (Collected, error) {
	var (
		mu  sync.Mutex
		res = Collected{Failed: map[string]bool{}}
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(concurrency, 1))
	for _, u := range fetchUnits(products) {
		for _, src := range srcs {
			inCluster := sources.InCluster(src)
			if inCluster && !u.local {
				continue
			}
			since := sinceFor(src.Name())
			g.Go(func() error {
				fs, err := fetch(gctx, src, u, since, log)
				mu.Lock()
				defer mu.Unlock()
				res.add(src, u, since, fs, err)
				if err != nil && gctx.Err() != nil {
					return gctx.Err()
				}
				return nil
			})
		}
	}
	if err := g.Wait(); err != nil {
		return Collected{}, err
	}
	if err := ctx.Err(); err != nil {
		return Collected{}, err
	}
	slices.Sort(res.Warnings)
	return res, nil
}

// fetch asks one source about one fetch unit. A source that panics on odd
// data fails like any source.
func fetch(ctx context.Context, src sources.Source, u *fetchUnit, since time.Time, log *slog.Logger) ([]finding.Finding, error) {
	start := time.Now()
	fs, err := safe.Call(func() ([]finding.Finding, error) { return src.Fetch(ctx, u.sel, since) })
	for i := range fs {
		fs[i].TagSource()
	}
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("source failed", "source", src.Name(), "product", u.sel.Product, "err", err)
		}
		return fs, err
	}
	log.Debug("source done", "source", src.Name(), "product", u.sel.Product, "findings", len(fs), "took", time.Since(start).Round(time.Millisecond))
	return fs, nil
}

// add records what one source returned for one fetch unit, copied to every
// scope that runs it.
func (res *Collected) add(src sources.Source, u *fetchUnit, since time.Time, fs []finding.Finding, err error) {
	inCluster := sources.InCluster(src)
	res.Raw = append(res.Raw, fs...)
	for _, p := range u.products {
		if inCluster && p.Scope.Remote {
			continue
		}
		for _, f := range fs {
			f = f.Clone()
			f.Product = p.Key()
			res.Findings = append(res.Findings, f)
		}
		if err != nil {
			res.Failed[p.Key()] = true
		}
	}
	if err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s/%s: %v", src.Name(), u.sel.Product, err))
		res.failures = append(res.failures, failedFetch{src: src, unit: u, since: since})
	}
}

// FailedSources returns the names of the sources with a failed fetch.
func (res *Collected) FailedSources() map[string]bool {
	out := map[string]bool{}
	for _, f := range res.failures {
		out[f.src.Name()] = true
	}
	return out
}

// RetryFailed asks every source that failed in cols once more, after wait:
// most failures are a feed's short outage (NVD's 503s), and a fetch still
// missing at the end keeps the window start where it is. A fetch that
// succeeds now loses its warning; Failed keeps only the products whose
// sources still fail. A zero wait or nothing failed: nothing to do.
func RetryFailed(ctx context.Context, wait time.Duration, concurrency int, log *slog.Logger, cols ...*Collected) error {
	n := 0
	for _, c := range cols {
		n += len(c.failures)
	}
	if wait <= 0 || n == 0 {
		return nil
	}
	log.Info("sources failed, asking them again", "fetches", n, "after", wait.String())
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
	}
	recovered := 0
	for _, c := range cols {
		type result struct {
			fs  []finding.Finding
			err error
		}
		out := make([]result, len(c.failures))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(max(concurrency, 1))
		for i, f := range c.failures {
			g.Go(func() error {
				fs, err := fetch(gctx, f.src, f.unit, f.since, log)
				out[i] = result{fs, err}
				return nil
			})
		}
		_ = g.Wait()
		if err := ctx.Err(); err != nil {
			return err
		}
		// Every warning and Failed entry came from a failure: rebuilt below.
		failures := c.failures
		c.failures, c.Warnings, c.Failed = nil, nil, map[string]bool{}
		for i, f := range failures {
			if out[i].err != nil {
				c.add(f.src, f.unit, f.since, out[i].fs, out[i].err)
				continue
			}
			recovered++
			c.add(f.src, f.unit, f.since, out[i].fs, nil)
		}
		slices.Sort(c.Warnings)
	}
	log.Info("sources asked again", "recovered", recovered, "still_failed", n-recovered)
	return nil
}

// MatchAll applies the deterministic version match per finding. A
// vulnerable package Trivy found in the running image makes the finding
// affected, whatever the advisory's version ranges say.
func MatchAll(fs []finding.Finding, byName map[string]catalog.Product) {
	for i := range fs {
		p := byName[fs[i].Product]
		res := match.Match(p.Constraint, fs[i].Affected, fs[i].AffectedVersions)
		if fs[i].MatchNote != "" && !fs[i].HasVersionData() && !p.Constraint.Any() {
			res.Detail = fs[i].MatchNote // why the source gave no version data
		}
		fs[i].Match, fs[i].MatchDetail = string(res.Status), res.Detail
		if fs[i].InImage() {
			detail := imageDetail(fs[i])
			if !fs[i].ImageOnly() && res.Status != match.Affected {
				detail += "; the advisory alone says: " + res.Detail
			}
			fs[i].Match, fs[i].MatchDetail = string(match.Affected), detail
		}
	}
}

// Options configures one run.
type Options struct {
	Config    *config.Config
	Products  []catalog.Product
	Sources   []sources.Source
	Enrichers []sources.Enricher
	Store     *state.Store
	Triager   *triage.Triager
	Outputs   []output.Output
	Log       *slog.Logger
	Now       func() time.Time

	Since     *time.Time // explicit window start (--since)
	DryRun    bool       // no state writes
	Bootstrap bool       // full-history check of every product, nothing reported as new, no LLM
	// WholeStack: Products is the whole stack (no --product), so baselines
	// of products no longer in it are deleted.
	WholeStack bool
}

// Run executes the full pipeline and returns the report it rendered.
// The returned error is non-nil only if the run as a whole failed, or if
// Claude answered none of its triage calls (the report is then rendered
// and the state written all the same).
func Run(ctx context.Context, o Options) (*report.Report, error) {
	now := o.Now().UTC()
	byName := map[string]catalog.Product{} // by Key()
	for _, p := range o.Products {
		byName[p.Key()] = p
	}

	// 3. Baselines and time window. Products that are new, or whose version
	// or catalog selectors changed, get their full advisory history checked;
	// the rest only what changed since the last run.
	stored, err := o.Store.Baselines(ctx)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var (
		baseProducts, deltaProducts []catalog.Product
		reasons                     = map[string]string{}
	)
	for _, p := range o.Products {
		if r := baselineReason(p, stored, o.Bootstrap, o.Config.Sources.Trivy.Enabled); r != "" {
			reasons[p.Key()] = r
			baseProducts = append(baseProducts, p)
			continue
		}
		deltaProducts = append(deltaProducts, p)
	}
	since, err := window(ctx, o, now)
	if err != nil {
		return nil, err
	}
	o.Log.Info("run started", "since", since.Format(time.RFC3339), "products", len(o.Products),
		"full_history", len(baseProducts), "dry_run", o.DryRun, "bootstrap", o.Bootstrap)

	// 4-6. Collect, normalize (done by sources), dedup.
	// A source that failed in an earlier run asks again from where it
	// stopped; the others from the run's window.
	behind, err := o.Store.SourceWindows(ctx)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	sinceFor := func(src string) time.Time {
		if t, ok := behind[src]; ok && t.Before(since) {
			return t
		}
		return since
	}
	for src, t := range behind {
		if t.Before(since) {
			o.Log.Info("source catching up after a failed run", "source", src, "since", t.Format(time.RFC3339))
		}
	}
	delta, err := CollectFrom(ctx, o.Sources, deltaProducts, sinceFor, o.Config.HTTP.MaxConcurrency, o.Log)
	if err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	full, err := Collect(ctx, o.Sources, baseProducts, time.Time{}, o.Config.HTTP.MaxConcurrency, o.Log)
	if err != nil {
		return nil, fmt.Errorf("collect full history: %w", err)
	}
	if err := RetryFailed(ctx, o.Config.Run.RetryFailedAfter.D(), o.Config.HTTP.MaxConcurrency, o.Log, &delta, &full); err != nil {
		return nil, fmt.Errorf("collect: %w", err)
	}
	raw := slices.Concat(delta.Raw, full.Raw)
	warnings := slices.Concat(delta.Warnings, full.Warnings)
	slices.Sort(warnings)
	fs := finding.Dedup(slices.Concat(delta.Findings, full.Findings))
	// Compared on full-history checks only: in a changes-only window each
	// source reports a record when it changes it, often on different days.
	var singleSource map[string]int
	if len(baseProducts) > 0 {
		singleSource = sourceCoverage(ctx, o.Log, finding.Dedup(slices.Clone(full.Findings)), o.Sources, byName, full.Warnings)
	}
	cleanFixed(fs)
	img := newImageState(o.Sources, warnings)
	img.note(fs)
	refresh, err := kevCandidates(ctx, o.Store, deltaProducts, fs, img)
	if err != nil {
		return nil, fmt.Errorf("state: KEV refresh: %w", err)
	}
	fs = img.dropUnfixedImageOnly(fs)
	o.Log.Info("collected", "raw", len(raw), "deduplicated", len(fs), "source_warnings", len(warnings))

	// 7. Enrich. The KEV catalog also goes over the earlier findings this
	// run didn't fetch (refresh); those it lists now are re-checked below.
	kevFailed := false
	for _, e := range o.Enrichers {
		target := fs
		if e.Name() == kev.Name {
			target = slices.Concat(fs, refresh)
			fs, refresh = target[:len(fs):len(fs)], target[len(fs):]
		}
		if err := e.Enrich(ctx, target); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			o.Log.Warn("enrichment failed", "source", e.Name(), "err", err)
			warnings = append(warnings, fmt.Sprintf("%s (enrichment): %v", e.Name(), err))
			kevFailed = kevFailed || e.Name() == kev.Name
		}
	}
	if kevFailed {
		if err := carryKEV(ctx, o.Store, fs); err != nil {
			return nil, fmt.Errorf("state lookup: %w", err)
		}
	}
	nKEV := len(fs)
	for _, f := range refresh {
		if f.KEV {
			fs = append(fs, f)
		}
	}
	if n := len(fs) - nKEV; n > 0 {
		o.Log.Info("open findings added to CISA KEV", "count", n)
	}

	// Image findings without an advisory, and kernel fixes: only those worth reporting.
	fs = img.filterImageOnly(fs, byName, o.Config.Sources.Trivy)
	fs, osFiltered := filterKernel(fs, o.Config.Sources.OS)

	// 8. Version match.
	MatchAll(fs, byName)

	// min_cvss threshold (KEV-listed findings are always kept; unknown scores too).
	var kept []finding.Finding
	below := 0
	summaries := map[string]*report.BaselineSummary{}
	for _, p := range baseProducts {
		summaries[p.Key()] = &report.BaselineSummary{
			Product: p.Name, Tenant: p.Scope.Tenant, Environment: p.Scope.Environment,
			Constraint: p.Constraint.String(), Reason: reasons[p.Key()], Complete: !full.Failed[p.Key()],
		}
	}
	for _, f := range fs {
		if b := summaries[f.Product]; b != nil {
			b.Checked++
		}
		if p := byName[f.Product]; f.CVSS > 0 && f.CVSS < p.MinCVSS && !f.KEV {
			below++
			continue
		}
		kept = append(kept, f)
	}

	// 9. Filter against state. For products checked against their full
	// history, findings not modified within the window (or all of them on
	// bootstrap) are history: recorded without being reported, listed under
	// Still open if they affect us. Recent ones take the normal new/changed
	// path, so a real change is never swallowed by a re-check.
	type pending struct {
		f       finding.Finding
		priorID string
		change  string
		first   time.Time // when it was first reported
	}
	type historic struct {
		f     finding.Finding
		prior *state.Prior
	}
	var (
		todo    []pending
		history []historic
		retry   []historic // unchanged, but Claude still owes a verdict
	)
	unchanged := 0
	for _, f := range kept {
		prior, err := o.Store.Lookup(ctx, f.Product, f.IDs())
		if err != nil {
			return nil, fmt.Errorf("state lookup: %w", err)
		}
		if b := summaries[f.Product]; b != nil {
			switch {
			case f.Match == string(match.Affected):
				b.Affected++
			case f.Match == string(match.Unknown) && !f.HasVersionData():
				b.NoData++
			case f.Match == string(match.Unknown):
				b.Unknown++
			}
			if f.KEV && f.Match != string(match.NotAffected) {
				b.KEV++
			}
			// Image findings of a re-checked product are history too: the
			// image (or Trivy) is new to us, the vulnerabilities are not.
			if o.Bootstrap || f.Modified.Before(since) || f.ImageOnly() || kernelOnly(f) {
				history = append(history, historic{f, prior})
				continue
			}
		}
		if prior == nil {
			todo = append(todo, pending{f: f, first: now})
			continue
		}
		changes := finding.Changes(prior.Snapshot, f.Snapshot())
		if len(changes) == 0 {
			unchanged++
			if prior.Detail != nil && prior.Detail.Untriaged && f.Match != string(match.NotAffected) {
				retry = append(retry, historic{f, prior})
			}
			continue
		}
		todo = append(todo, pending{f: f, priorID: prior.ID, change: strings.Join(changes, "; "), first: prior.FirstReported})
	}

	// 10. Triage (new and changed findings only; history never goes to Claude).
	items := make([]triage.Item, len(todo), len(todo)+len(history))
	for i, t := range todo {
		items[i] = triage.Item{Finding: t.f, Product: byName[t.f.Product]}
	}
	// History that is new to us and would be P1 is alerted like a new
	// finding, so it gets Claude's explanation too (usually a handful).
	for _, h := range history {
		it := triage.Item{Finding: h.f, Product: byName[h.f.Product]}
		if h.prior == nil && h.f.Match != string(match.NotAffected) && triage.Deterministic(it).Priority == "P1" {
			items = append(items, it)
		}
	}
	triager := o.Triager
	if o.Bootstrap || triager == nil {
		triager = triage.New(o.Config.Triage, nil, o.Log)
	}
	results, tst := triageShared(ctx, triager, items)
	// Findings Claude gave no verdict for in an earlier run get what is
	// left of the budget; they are not reported again, only updated. Not
	// after an API error: they stay owed for the next run.
	var retried map[string]triage.Result
	if left := triager.Budget() - llmCandidates(items); left > 0 && len(retry) > 0 && !tst.APIError {
		ritems := make([]triage.Item, len(retry))
		for i, r := range retry {
			ritems[i] = triage.Item{Finding: r.f, Product: byName[r.f.Product]}
		}
		var rst triage.Stats
		retried, rst = triageShared(ctx, triager.WithBudget(left), ritems)
		tst = tst.Add(rst)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Claude answered nothing (a bad key or model name, or the API down):
	// the run reports and stores the rule-based priorities, then fails, so
	// it is alerted on instead of passing as a quiet day.
	var triageErr error
	if tst.Dead() {
		triageErr = fmt.Errorf("triage: every Claude call failed (%d), priorities are rule-based; check the API key, triage.model and the log", tst.Failed)
	}

	// History: keep Claude's earlier verdict when there is one, otherwise the
	// rule-based priority. Findings without version data are only counted:
	// an old advisory without versions says nothing about our version.
	var (
		historyRecs []state.Record
		baseOpen    []report.OpenItem
		baseUnknown int
	)
	reportedNow := map[string]bool{}
	for _, t := range todo {
		reportedNow[t.f.Product+"/"+t.f.ID] = true
		reportedNow[t.f.Product+"/"+t.priorID] = true
	}
	for _, h := range history {
		p := byName[h.f.Product]
		var r *triage.Result
		if res, ok := results[p.Key()+"/"+h.f.ID]; ok {
			r = &res
		}
		d := baselineDetail(h.f, p, h.prior, r)
		first := now
		rec := state.Record{Product: h.f.Product, ID: h.f.ID, IDs: h.f.IDs(), Snapshot: h.f.Snapshot(), Detail: d}
		if h.prior != nil {
			rec.PriorID, first = h.prior.ID, h.prior.FirstReported
			reportedNow[h.f.Product+"/"+h.prior.ID] = true
		}
		reportedNow[h.f.Product+"/"+h.f.ID] = true
		historyRecs = append(historyRecs, rec)
		switch it, st := openItem(p, h.f.ID, d, first, h.f.InImage()); st {
		case openListed:
			it.FirstSeen = h.prior == nil
			baseOpen = append(baseOpen, it)
		case openCounted:
			baseUnknown++
		}
	}
	var retryRecs []state.Record
	for _, h := range retry {
		p := byName[h.f.Product]
		r, ok := retried[p.Key()+"/"+h.f.ID]
		if !ok || r.Method != triage.MethodLLM {
			continue // still owed: listed from state as before
		}
		d := triageDetail(h.f, p, r, h.prior.Detail.Constraint)
		retryRecs = append(retryRecs, state.Record{Product: h.f.Product, ID: h.f.ID, IDs: h.f.IDs(), PriorID: h.prior.ID, Snapshot: h.f.Snapshot(), Detail: d})
		reportedNow[h.f.Product+"/"+h.f.ID], reportedNow[h.f.Product+"/"+h.prior.ID] = true, true
		switch it, st := openItem(p, h.f.ID, d, h.prior.FirstReported, h.f.InImage()); st {
		case openListed:
			baseOpen = append(baseOpen, it)
		case openCounted:
			baseUnknown++
		}
	}

	// Still open: findings reported earlier that still affect the stack.
	open, openUnknown, err := stillOpen(ctx, o.Store, byName, reportedNow, img, o.Log)
	if err != nil {
		return nil, fmt.Errorf("state: still open: %w", err)
	}
	open, openUnknown = append(open, baseOpen...), openUnknown+baseUnknown

	// 11. Report.
	entries := make([]report.Entry, len(todo))
	for i, t := range todo {
		entries[i] = report.Entry{Finding: t.f, Product: items[i].Product, Triage: results[items[i].Key()], Change: t.change, FirstReported: t.first}
	}
	var baselines []report.BaselineSummary
	for _, p := range baseProducts {
		baselines = append(baselines, *summaries[p.Key()])
	}
	stats := sourceStats(o.Sources, o.Enrichers, raw, warnings)
	meta := report.Meta{
		Mode: report.ModeRun, GeneratedAt: now, Since: since, Until: now, Products: o.Products,
		BelowThreshold: below, Unchanged: unchanged, Warnings: warnings,
		Open: open, OpenUnknown: openUnknown, Sources: stats, Baselines: baselines,
		Links:         AdvisoryLinks(o.Config),
		ImageFiltered: img.filtered, UnmatchedImages: img.unmatched, KernelFiltered: osFiltered,
		SingleSource:   singleSource,
		TriageFailures: tst.Failed,
	}
	switch {
	case o.Bootstrap:
		meta.Mode = report.ModeBootstrap
	case o.DryRun:
		meta.Mode = report.ModeDryRun
	}
	rep := report.Build(meta, entries)

	var outErrs []error
	for _, out := range o.Outputs {
		if err := out.Render(ctx, rep); err != nil {
			o.Log.Error("output failed", "output", out.Name(), "err", err)
			outErrs = append(outErrs, fmt.Errorf("output %s: %w", out.Name(), err))
		}
	}
	if err := errors.Join(outErrs...); err != nil {
		return &rep, err
	}
	if err := ctx.Err(); err != nil {
		return &rep, err
	}
	auditReported(ctx, o.Log, entries, open, meta.Mode)

	// 12. Persist: only after every output succeeded. A baseline counts as
	// done only if every source answered for that product.
	if o.DryRun {
		o.Log.Info("dry run: state not updated")
		return &rep, triageErr
	}
	recs := make([]state.Record, 0, len(todo)+len(historyRecs)+len(retryRecs))
	for i, t := range todo {
		r := results[items[i].Key()]
		recs = append(recs, state.Record{
			Product: t.f.Product, ID: t.f.ID, IDs: t.f.IDs(), PriorID: t.priorID, Snapshot: t.f.Snapshot(),
			Detail: triageDetail(t.f, items[i].Product, r, items[i].Product.Constraint.String()),
		})
	}
	recs = append(recs, historyRecs...)
	recs = append(recs, retryRecs...)
	var done []state.Baseline
	for _, p := range baseProducts {
		if full.Failed[p.Key()] {
			o.Log.Warn("full-history check incomplete, retried next run", "product", p.Key())
			continue
		}
		done = append(done, state.Baseline{Product: p.Key(), Constraint: p.Constraint.String(), Fingerprint: fingerprint(p, o.Config.Sources.Trivy.Enabled)})
	}
	// A source that failed for a product checked only for changes would
	// lose that window's advisories: it keeps its own window start, and the
	// next run asks it again from there. The run's window and the other
	// sources move on (VulnwatchSourceFailing tells while it lasts).
	failedSrc := delta.FailedSources()
	var windows []state.SourceWindow
	for _, src := range o.Sources {
		name := src.Name()
		switch {
		case failedSrc[name]:
			windows = append(windows, state.SourceWindow{Source: name, Since: sinceFor(name)})
		case len(deltaProducts) > 0 && !behind[name].IsZero():
			windows = append(windows, state.SourceWindow{Source: name}) // caught up
		}
	}
	if len(failedSrc) > 0 {
		o.Log.Warn("sources failed: they keep their window start and ask again from there next run",
			"sources", slices.Sorted(maps.Keys(failedSrc)), "products", len(delta.Failed))
	}
	if err := o.Store.Commit(ctx, now, recs, done, true, windows...); err != nil {
		return &rep, fmt.Errorf("persist state: %w", err)
	}
	// A product removed and added again gets its full history checked anew.
	if o.WholeStack {
		gone, err := o.Store.PruneBaselines(ctx, slices.Collect(maps.Keys(byName)))
		if err != nil {
			return &rep, fmt.Errorf("persist state: %w", err)
		}
		if len(gone) > 0 {
			o.Log.Info("baselines of removed products deleted", "products", gone)
		}
	}
	logx.Audit(ctx, o.Log, "state written", "reported", len(todo), "history", len(historyRecs), "retriaged", len(retryRecs), "baselines", len(done))
	o.Log.Info("run finished", "reported", len(todo), "history", len(historyRecs), "retriaged", len(retryRecs), "baselines", len(done),
		"unchanged", unchanged, "below_threshold", below, "still_open", len(open), "warnings", len(warnings))
	return &rep, triageErr
}

// auditReported records what the run reported: every new or changed
// finding (priority and how it was decided) and every P1 the full-history
// check found, which is alerted like a new one.
func auditReported(ctx context.Context, log *slog.Logger, entries []report.Entry, open []report.OpenItem, mode string) {
	for _, e := range entries {
		p := e.Product
		logx.Audit(ctx, log, "finding reported", "mode", mode, "tenant", p.Scope.Tenant, "environment", p.Scope.Environment,
			"product", p.Name, "version", p.Constraint.String(), "id", e.Finding.ID, "priority", e.Triage.Priority,
			"relevant", e.Triage.Relevant, "decided_by", e.Triage.Method, "change", cmp.Or(e.Change, "new"),
			"kev", e.Finding.KEV, "cvss", e.Finding.CVSS)
	}
	for _, it := range open {
		if it.FirstSeen && it.Priority == "P1" {
			logx.Audit(ctx, log, "finding reported", "mode", mode, "tenant", it.Tenant, "environment", it.Environment,
				"product", it.Product, "version", it.Constraint, "id", it.ID, "priority", it.Priority,
				"change", "found by the full-history check", "kev", it.KEV, "cvss", it.CVSS)
		}
	}
}

// triageShared triages each distinct finding once: tenants running the same
// version with the same exposure and criticality share Claude's verdict
// (one call instead of one per tenant). Results are keyed by Item.Key().
func triageShared(ctx context.Context, t *triage.Triager, items []triage.Item) (map[string]triage.Result, triage.Stats) {
	key := shareKey
	rep := map[shareSig]triage.Item{}
	var unique []triage.Item
	for _, it := range items {
		k := key(it)
		if _, ok := rep[k]; ok {
			continue
		}
		rep[k] = it
		unique = append(unique, it)
	}
	if len(unique) == len(items) {
		return t.Triage(ctx, items)
	}
	res, st := t.Triage(ctx, unique)
	out := make(map[string]triage.Result, len(items))
	for _, it := range items {
		if r, ok := res[rep[key(it)].Key()]; ok {
			out[it.Key()] = r
		}
	}
	return out, st
}

// shareSig is what makes two items share Claude's verdict (triageShared).
type shareSig struct{ name, id, constraint, exposure, criticality, match string }

func shareKey(it triage.Item) shareSig {
	p := it.Product
	return shareSig{p.Name, it.Finding.ID, p.Constraint.String(), p.Exposure, p.Criticality, it.Finding.Match}
}

// llmCandidates counts the findings triageShared offers Claude: the
// distinct ones that may affect us.
func llmCandidates(items []triage.Item) int {
	seen := map[shareSig]bool{}
	for _, it := range items {
		if it.Finding.Match != string(match.NotAffected) {
			seen[shareKey(it)] = true
		}
	}
	return len(seen)
}

// sourceStats counts raw findings and failures per source. Failures are
// read from the warnings, which start with "<source>/<product>:" (collect)
// or "<source> (enrichment):".
func sourceStats(srcs []sources.Source, enr []sources.Enricher, raw []finding.Finding, warnings []string) []report.SourceStat {
	idx := map[string]int{}
	var out []report.SourceStat
	add := func(name string) {
		if _, ok := idx[name]; !ok {
			idx[name] = len(out)
			out = append(out, report.SourceStat{Name: name})
		}
	}
	for _, s := range srcs {
		add(s.Name())
	}
	for _, e := range enr {
		add(e.Name())
	}
	for _, f := range raw {
		if len(f.Sources) > 0 {
			add(f.Sources[0])
			out[idx[f.Sources[0]]].Findings++
		}
	}
	for _, w := range warnings {
		name, _, _ := strings.Cut(w, "/")
		name, _, _ = strings.Cut(name, " ")
		if i, ok := idx[name]; ok {
			out[i].Errors++
		}
	}
	slices.SortFunc(out, func(a, b report.SourceStat) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// stillOpen re-matches every earlier reported finding against the current
// stack (see openItem). Findings handled in this run (skip) are listed with
// the new ones or the baseline instead.
// Image-only findings stay open exactly while Trivy still finds them; when
// the image source didn't answer, they are kept as they were. Findings
// whose CVE IDs the CVE list has all rejected are closed.
func stillOpen(ctx context.Context, store *state.Store, byName map[string]catalog.Product, skip map[string]bool, img imageState, log *slog.Logger) ([]report.OpenItem, int, error) {
	recs, err := store.ListReported(ctx)
	if err != nil {
		return nil, 0, err
	}
	var cves []string
	for _, r := range recs {
		cves = append(cves, r.Detail.Finding.CVEs()...)
	}
	rejected, err := store.CVEListRejected(ctx, cves)
	if err != nil {
		return nil, 0, err
	}
	var (
		open    []report.OpenItem
		unknown int
	)
	for _, r := range recs {
		p, ok := byName[r.Product]
		if !ok || skip[r.Product+"/"+r.ID] {
			continue
		}
		if ids := r.Detail.Finding.CVEs(); len(ids) > 0 && !slices.ContainsFunc(ids, func(id string) bool { return !rejected[id] }) {
			logx.Audit(ctx, log, "advisory rejected", "tenant", p.Scope.Tenant, "environment", p.Scope.Environment,
				"product", p.Name, "id", r.ID, "rejected", ids)
			continue
		}
		inImage := false
		if r.Detail.Finding.ImageOnly() {
			running, ok := img.stillRunning(r.Product, r.ID)
			if ok && !running {
				continue // fixed: no running image contains it any more
			}
			inImage = true
		}
		switch it, st := openItem(p, r.ID, r.Detail, r.FirstReported, inImage); st {
		case openListed:
			open = append(open, it)
		case openCounted:
			unknown++
		}
	}
	return open, unknown, nil
}

// kevCandidates returns the earlier findings of the products checked for
// changes only that this run didn't fetch, aren't KEV-listed and may still
// affect the stack. Those the KEV catalog lists now take the changed path
// ("added to CISA KEV"): an open finding escalates when it is exploited.
func kevCandidates(ctx context.Context, store *state.Store, products []catalog.Product, fetched []finding.Finding, img imageState) ([]finding.Finding, error) {
	if len(products) == 0 {
		return nil, nil
	}
	byName := make(map[string]catalog.Product, len(products))
	for _, p := range products {
		byName[p.Key()] = p
	}
	seen := map[string]bool{}
	for _, f := range fetched {
		for _, id := range f.IDs() {
			seen[f.Product+"/"+id] = true
		}
	}
	recs, err := store.ListReported(ctx)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, r := range recs {
		p, ok := byName[r.Product]
		f := r.Detail.Finding
		if !ok || f.KEV || len(f.CVEs()) == 0 || seen[r.Product+"/"+r.ID] ||
			slices.ContainsFunc(f.IDs(), func(id string) bool { return seen[r.Product+"/"+id] }) {
			continue
		}
		if f.ImageOnly() {
			if running, ok := img.stillRunning(r.Product, r.ID); ok && !running {
				continue
			}
		} else if match.Match(p.Constraint, f.Affected, f.AffectedVersions).Status == match.NotAffected {
			continue
		}
		f = f.Clone()
		f.Product = r.Product
		out = append(out, f)
	}
	return out, nil
}

// carryKEV keeps the stored KEV flag when the KEV catalog couldn't be read
// at all: otherwise the flag is lost now and its return is reported as
// "added to CISA KEV".
func carryKEV(ctx context.Context, store *state.Store, fs []finding.Finding) error {
	for i := range fs {
		if fs[i].KEV {
			continue
		}
		prior, err := store.Lookup(ctx, fs[i].Product, fs[i].IDs())
		if err != nil {
			return err
		}
		if prior == nil || !prior.Snapshot.KEV {
			continue
		}
		fs[i].KEV = true
		if prior.Detail != nil {
			fs[i].KEVDateAdded = prior.Detail.Finding.KEVDateAdded
		}
	}
	return nil
}

func cleanFixed(fs []finding.Finding) {
	for i := range fs {
		fs[i].Fixed = sources.CleanFixed(fs[i].Fixed)
	}
}

// AdvisoryLinks returns the advisory page templates from sources.yaml.
func AdvisoryLinks(cfg *config.Config) report.AdvisoryLinks {
	if cfg == nil {
		return report.AdvisoryLinks{}
	}
	return report.AdvisoryLinks{NVD: cfg.Sources.NVD.DetailURL, GitHub: cfg.Sources.GHSA.DetailURL}
}

// Outcomes of openItem.
const (
	openDropped = iota // not affected, not relevant or below min_cvss
	openCounted        // can't be tracked: counted, not listed
	openListed         // affects (or may affect) the deployed version
)

// openItem decides whether a known finding still affects the product as
// deployed now. Products tracked with "*" never clear, so their findings are
// only counted. Findings without version data stay listed while the version
// recorded with them (Detail.Constraint) is still the deployed one. A
// finding in a running image (inImage) is affected.
func openItem(p catalog.Product, id string, d state.Detail, firstReported time.Time, inImage bool) (report.OpenItem, int) {
	f := d.Finding
	if d.Method == triage.MethodLLM && d.Relevant == "no" {
		return report.OpenItem{}, openDropped
	}
	if f.CVSS > 0 && f.CVSS < p.MinCVSS && !f.KEV {
		return report.OpenItem{}, openDropped
	}
	res := match.Match(p.Constraint, f.Affected, f.AffectedVersions)
	if inImage {
		res = match.Result{Status: match.Affected, Detail: imageDetail(f)}
	}
	f.Match, f.MatchDetail = string(res.Status), res.Detail
	noData := !f.HasVersionData() && !inImage
	switch {
	case res.Status == match.NotAffected:
		return report.OpenItem{}, openDropped
	case res.Status == match.Unknown && p.Constraint.Any():
		return report.OpenItem{}, openCounted
	case res.Status == match.Unknown && noData && (d.Constraint == "" || d.Constraint != p.Constraint.String()):
		return report.OpenItem{}, openCounted
	}
	prio := d.Priority
	rule := triage.Deterministic(triage.Item{Finding: f, Product: p}).Priority
	switch {
	case d.Method != triage.MethodLLM:
		// Rule-based priorities (legacy "fallback" rows included) depend on
		// the match and the product settings, both of which may have changed.
		prio = rule
	case d.Exposure != "" && (d.Exposure != p.Exposure || d.Criticality != p.Criticality):
		// Claude decided for other settings: the more urgent of its verdict
		// and the rules now.
		prio = min(prio, rule)
	}
	it := report.OpenItem{
		ID: id, Product: p.Name, Tenant: p.Scope.Tenant, Environment: p.Scope.Environment,
		Constraint: p.Constraint.String(), Title: f.Title, Fixed: f.Fixed,
		CVSS: f.CVSS, Severity: f.Severity, KEV: f.KEV, EPSS: f.EPSS, Match: f.Match, NoVersionData: noData, Priority: prio,
		FirstReported: firstReported,
		Aliases:       slices.DeleteFunc(f.IDs(), func(a string) bool { return a == id }),
		ImageOnly:     f.ImageOnly(),
		References:    f.References,
		Summary:       d.Summary,
		Action:        d.Action,
	}
	if inImage {
		it.Packages = f.Packages
	}
	if len(f.References) > 0 {
		it.Link = f.References[0]
	}
	return it, openListed
}

// baselineReason says why a product needs a full-history check, or "".
func baselineReason(p catalog.Product, stored map[string]state.Baseline, bootstrap, trivyOn bool) string {
	b, ok := stored[p.Key()]
	switch {
	case bootstrap:
		return report.BaselineBootstrap
	case !ok:
		return report.BaselineNew
	case b.Constraint != p.Constraint.String():
		return report.BaselineVersionChanged
	case b.Fingerprint == fingerprintAt(p, trivyOn, matchingVersion-1):
		return report.BaselineMatching
	case b.Fingerprint != fingerprint(p, trivyOn):
		return report.BaselineSourcesChanged
	}
	return ""
}

// matchingVersion is part of every baseline's fingerprint. Bump it in a
// release that changes how sources read advisories (ranges, fixed versions,
// product names): the daily window never fetches old advisories again, so
// findings stored with the old reading would stay open (or hidden) for
// good. The bump re-checks every product's full history once, which
// rewrites them. 1: GHSA ranges per release line, Go major caps, cvelist
// "n/a" vendors (v0.10.0, v0.11.0).
const matchingVersion = 1

// fingerprint identifies what a baseline covered: the deployed version(s),
// the catalog selectors, whether Trivy reads the product's images (adding
// a source re-checks the history; turning Trivy on records the image
// findings found then as history instead of reporting them) and the
// matching version.
func fingerprint(p catalog.Product, trivyOn bool) string {
	return fingerprintAt(p, trivyOn, matchingVersion)
}

func fingerprintAt(p catalog.Product, trivyOn bool, matching int) string {
	v := struct {
		Constraint string
		Entry      config.CatalogEntry
		Trivy      bool            `json:",omitempty"`
		OS         *config.StackOS `json:",omitempty"`
		Matching   int             `json:",omitempty"` // 0: baselines from before v0.12.0
	}{p.Constraint.String(), p.Entry, trivyOn && len(p.Entry.Images) > 0, p.OS, matching}
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// baselineDetail is the stored detail for a finding from a full-history
// check: Claude's earlier verdict if there is one, otherwise rule-based by
// design (MethodRules, never retried), or a fallback when Claude was asked
// in this run and gave no verdict. Without version data the constraint
// stays empty, so the finding is only counted: an old advisory without
// versions says nothing about ours.
func baselineDetail(f finding.Finding, p catalog.Product, prior *state.Prior, r *triage.Result) state.Detail {
	constraint := p.Constraint.String()
	if !f.HasVersionData() {
		constraint = ""
	}
	if r != nil && r.Method == triage.MethodLLM {
		return triageDetail(f, p, *r, constraint)
	}
	if prior != nil && prior.Detail != nil && prior.Detail.Method == triage.MethodLLM {
		d := prior.Detail
		nd := state.NewDetail(f, d.Priority, d.Relevant, d.Method, constraint)
		nd.Summary, nd.Action = d.Summary, d.Action
		nd.Exposure, nd.Criticality = d.Exposure, d.Criticality // what Claude decided for
		return nd
	}
	if r != nil && r.Method == triage.MethodFallback {
		return triageDetail(f, p, *r, constraint)
	}
	rule := triage.Deterministic(triage.Item{Finding: f, Product: p})
	rule.Method = triage.MethodRules
	return triageDetail(f, p, rule, constraint)
}

// triageDetail is the stored detail of a triage result, with the product
// settings it was decided for; a fallback is marked as still owed by Claude.
func triageDetail(f finding.Finding, p catalog.Product, r triage.Result, constraint string) state.Detail {
	d := withExplanation(state.NewDetail(f, r.Priority, r.Relevant, r.Method, constraint), r)
	d.Exposure, d.Criticality = p.Exposure, p.Criticality
	d.Untriaged = r.Method == triage.MethodFallback
	return d
}

func window(ctx context.Context, o Options, now time.Time) (time.Time, error) {
	if o.Since != nil {
		return o.Since.UTC(), nil
	}
	last, ok, err := o.Store.LastSuccess(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("read state: %w", err)
	}
	overlap := o.Config.Run.Overlap.D()
	if !ok {
		// First run: every product gets a full-history check anyway; the
		// window only decides what counts as new.
		return now.Add(-overlap), nil
	}
	return last.Add(-overlap), nil
}

func selector(p catalog.Product) sources.Selector {
	sel := sources.Selector{Product: p.Name, Entry: p.Entry, OS: p.OS}
	if p.OS != nil {
		for _, alt := range p.Constraint.Alternatives() {
			sel.Versions = append(sel.Versions, alt.String())
		}
	}
	return sel
}

// kernelOnly reports whether only the OS tracker reports the finding: a
// kernel fix of the nodes' distribution.
func kernelOnly(f finding.Finding) bool {
	return len(f.Sources) > 0 && !slices.ContainsFunc(f.Sources, func(s string) bool { return s != ostracker.Name })
}

// filterKernel keeps the kernel fixes worth reporting: KEV-listed or
// EPSS >= min_epss. The tracker lists hundreds per release.
func filterKernel(fs []finding.Finding, cfg config.OSSource) ([]finding.Finding, int) {
	n := 0
	fs = slices.DeleteFunc(fs, func(f finding.Finding) bool {
		if !kernelOnly(f) || f.KEV || (cfg.MinEPSS > 0 && f.EPSS >= cfg.MinEPSS) {
			return false
		}
		n++
		return true
	})
	return fs, n
}

// withExplanation keeps Claude's summary and action with the finding, for
// when it is listed (and alerted) as still open.
func withExplanation(d state.Detail, r triage.Result) state.Detail {
	if r.Method == triage.MethodLLM {
		d.Summary, d.Action = r.Summary, r.Action
	}
	return d
}
