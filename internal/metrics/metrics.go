// Package metrics turns one vulnwatch run into Prometheus metrics. vulnwatch
// is a batch job, so the metrics are pushed to a Pushgateway (replacing the
// previous run's group, or only its health metrics when the run failed
// before a report was built) or written to a file in the text format.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/push"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
	"github.com/vasops/vulnwatch/version"
)

// Run describes one finished (or failed) run.
type Run struct {
	Mode        string         // run | bootstrap
	Report      *report.Report // nil if the run failed before a report was built
	Products    []catalog.Product
	Err         error
	Start, End  time.Time
	LastSuccess time.Time // from the state DB after the run; zero if never
}

// Metrics is a run's registry. HealthOnly is set when the run has no report:
// it holds only the health families (run, build, tenant and product info),
// so a push must update those and keep the last report's finding families
// instead of replacing the group (and resolving every finding alert).
type Metrics struct {
	*prometheus.Registry
	HealthOnly bool
}

// Registry builds a fresh registry holding the run's metrics. Every series
// is a gauge describing the latest run, because a push replaces the group.
func Registry(r Run) *Metrics {
	reg := prometheus.NewRegistry()
	gauge := func(name, help string, labels ...string) *prometheus.GaugeVec {
		g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: "vulnwatch", Name: name, Help: help}, labels)
		reg.MustRegister(g)
		return g
	}
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}

	gauge("build_info", "Build information; always 1.", "version", "commit").
		WithLabelValues(version.Version, version.Commit).Set(1)
	gauge("run_timestamp_seconds", "When the last run finished.", "mode").WithLabelValues(r.Mode).Set(float64(r.End.Unix()))
	gauge("run_duration_seconds", "Duration of the last run.", "mode").WithLabelValues(r.Mode).Set(r.End.Sub(r.Start).Seconds())
	gauge("run_success", "1 if the last run completed and every output succeeded.", "mode").WithLabelValues(r.Mode).Set(b2f(r.Err == nil))
	if !r.LastSuccess.IsZero() {
		gauge("last_success_timestamp_seconds", "When the last fully successful run finished.").WithLabelValues().Set(float64(r.LastSuccess.Unix()))
	}

	// Every product series carries the tenant and environment it runs in
	// (the local stack: stack.yaml tenant/environment, default local/default).
	tenants := gauge("tenant_info", "Tenant environments being watched; local=true for the cluster vulnwatch runs in; always 1.",
		"tenant", "environment", "local")
	inventory := gauge("tenant_inventory_timestamp_seconds", "When the stack of each tenant environment was read from its cluster (stack.yaml generated_at, 00:00 UTC); only for the ones that have it.",
		"tenant", "environment")
	seen := map[[2]string]bool{}
	for _, p := range r.Products {
		t, e := scopeLabels(p.Scope.Tenant, p.Scope.Environment)
		k := [2]string{t, e}
		if !seen[k] {
			seen[k] = true
			tenants.WithLabelValues(k[0], k[1], strconv.FormatBool(!p.Scope.Remote)).Set(1)
			if !p.Scope.GeneratedAt.IsZero() {
				inventory.WithLabelValues(k[0], k[1]).Set(float64(p.Scope.GeneratedAt.Unix()))
			}
		}
	}
	info := gauge("product_info", "Products being watched and their version constraints; always 1.",
		"tenant", "environment", "product", "constraint", "exposure", "criticality")
	for _, p := range r.Products {
		t, e := scopeLabels(p.Scope.Tenant, p.Scope.Environment)
		info.WithLabelValues(t, e, p.Name, p.Constraint.String(), p.Exposure, p.Criticality).Set(1)
	}

	rep := r.Report
	if rep == nil {
		return &Metrics{Registry: reg, HealthOnly: true}
	}
	newF := gauge("findings_new", "Findings reported in the last run (new or materially changed), by tenant, environment and priority.",
		"tenant", "environment", "priority")
	newBy := map[[3]string]int{}
	for k := range seen {
		for _, prio := range triage.Priorities {
			newBy[[3]string{k[0], k[1], prio}] = 0
		}
	}
	for _, it := range rep.Items() {
		t, e := scopeLabels(it.Tenant, it.Environment)
		newBy[[3]string{t, e, it.Priority}]++
	}
	if len(newBy) == 0 {
		for _, c := range rep.Counts {
			t, e := scopeLabels("", "")
			newBy[[3]string{t, e, c.Priority}] = c.Count
		}
	}
	for k, n := range newBy {
		newF.WithLabelValues(k[0], k[1], k[2]).Set(float64(n))
	}
	skipped := gauge("findings_skipped", "Findings not listed in the last run, by reason.", "reason")
	skipped.WithLabelValues("not_relevant").Set(float64(rep.NotRelevant))
	skipped.WithLabelValues("below_threshold").Set(float64(rep.BelowThreshold))
	skipped.WithLabelValues("already_reported").Set(float64(rep.Unchanged))
	skipped.WithLabelValues("open_without_version_data").Set(float64(rep.OpenUnknown))

	// Open = still open from earlier runs + listed in this run. Every
	// product/priority pair is set (0 included) so panels and alerts see
	// a value, not an absent series.
	open := gauge("findings_open", "Findings currently affecting the stack (new in this run or still open), by product and priority.", "tenant", "environment", "product", "priority")
	openKEV := gauge("findings_open_kev", "Open findings listed in CISA KEV (exploited in the wild), by product.", "tenant", "environment", "product")
	oldest := gauge("findings_open_oldest_days", "Days since vulnwatch first reported the oldest open finding, by product.", "tenant", "environment", "product")
	untriaged := gauge("findings_untriaged", "Findings in the last run that Claude did not triage (rule-based priority).")
	type agg struct {
		byPrio  map[string]int
		kev     int
		oldDays int
	}
	per := map[[3]string]*agg{} // tenant, environment, product
	for _, p := range r.Products {
		t, e := scopeLabels(p.Scope.Tenant, p.Scope.Environment)
		per[[3]string{t, e, p.Name}] = &agg{byPrio: map[string]int{}}
	}
	get := func(tenant, env, name string) *agg {
		t, e := scopeLabels(tenant, env)
		k := [3]string{t, e, name}
		if per[k] == nil {
			per[k] = &agg{byPrio: map[string]int{}}
		}
		return per[k]
	}
	nUntriaged := 0
	for _, it := range rep.Items() {
		a := get(it.Tenant, it.Environment, it.Product)
		a.byPrio[it.Priority]++
		if it.KEV {
			a.kev++
		}
		if !it.Triaged {
			nUntriaged++
		}
		// A finding listed again (e.g. a fix was released) keeps its age.
		a.oldDays = max(a.oldDays, int(rep.GeneratedAt.Sub(it.FirstReported).Hours()/24))
	}
	for _, it := range rep.Open {
		a := get(it.Tenant, it.Environment, it.Product)
		a.byPrio[it.Priority]++
		if it.KEV {
			a.kev++
		}
		a.oldDays = max(a.oldDays, it.DaysOpen)
	}
	untriaged.WithLabelValues().Set(float64(nUntriaged))
	gauge("triage_failures", "Claude triage calls (batches) that failed in the last run: API error, or invalid output after the retry; their findings got the rule-based priority.").
		WithLabelValues().Set(float64(rep.TriageFailures))
	if tu := rep.TriageUsage; tu != nil {
		gauge("triage_requests", "Claude triage requests that got a response in the last run, by model.", "model").
			WithLabelValues(tu.Model).Set(float64(tu.Requests))
		tokens := gauge("triage_tokens", "Tokens the Claude triage used in the last run, by model and type (input, output, cache_creation, cache_read).", "model", "type")
		tokens.WithLabelValues(tu.Model, "input").Set(float64(tu.InputTokens))
		tokens.WithLabelValues(tu.Model, "output").Set(float64(tu.OutputTokens))
		tokens.WithLabelValues(tu.Model, "cache_creation").Set(float64(tu.CacheCreationInputTokens))
		tokens.WithLabelValues(tu.Model, "cache_read").Set(float64(tu.CacheReadInputTokens))
	}
	for k, a := range per {
		for _, prio := range triage.Priorities {
			open.WithLabelValues(k[0], k[1], k[2], prio).Set(float64(a.byPrio[prio]))
		}
		openKEV.WithLabelValues(k[0], k[1], k[2]).Set(float64(a.kev))
		oldest.WithLabelValues(k[0], k[1], k[2]).Set(float64(a.oldDays))
	}

	// The one series per open finding, valued with the time it was first
	// reported: dashboards list the findings with their NVD and GitHub links
	// and "what was discovered when". The labels only change when the
	// finding does (no new/open status), so a finding keeps its series from
	// the run that reports it until it is fixed. Every label is a table
	// column; keep it that way, a Pushgateway holds them all in memory.
	findingReported := gauge("finding_first_reported_timestamp_seconds", "Findings currently affecting the stack, one series each, with their NVD and GitHub advisory pages; the value is when vulnwatch first reported it (Unix seconds).",
		"tenant", "environment", "product", "constraint", "id", "title", "priority", "severity", "cvss", "kev", "fixed", "image", "nvd_url", "github_url")
	for _, it := range rep.Items() {
		nvd, gh := advisoryURLs(it.Advisories)
		t, e := scopeLabels(it.Tenant, it.Environment)
		findingReported.WithLabelValues(t, e, it.Product, it.Constraint, it.ID, it.Title, it.Priority, it.Severity, cvss(it.CVSS),
			strconv.FormatBool(it.KEV), strings.Join(it.Fixed, ", "), imageLabel(len(it.Packages) > 0, it.ImageOnly), nvd, gh).
			Set(float64(cmpTime(it.FirstReported, rep.GeneratedAt).Unix()))
	}
	for _, it := range rep.Open {
		nvd, gh := advisoryURLs(it.Advisories)
		t, e := scopeLabels(it.Tenant, it.Environment)
		findingReported.WithLabelValues(t, e, it.Product, it.Constraint, it.ID, it.Title, it.Priority, it.Severity, cvss(it.CVSS),
			strconv.FormatBool(it.KEV), strings.Join(it.Fixed, ", "), imageLabel(len(it.Packages) > 0, it.ImageOnly), nvd, gh).
			Set(float64(cmpTime(it.FirstReported, rep.GeneratedAt).Unix()))
	}

	upgrade := gauge("product_upgrade_info", "Per product with open findings: the version that fixes every open finding with a known fix; always 1.",
		"tenant", "environment", "product", "constraint", "upgrade_to")
	unfixed := gauge("findings_open_unfixed", "Open findings without any fixed version, by product.", "tenant", "environment", "product")
	imageOnly := gauge("findings_open_image_only", "Open findings only Trivy reports (a package in the running image, fixed by a newer image), by product.", "tenant", "environment", "product")
	for _, u := range rep.Upgrades() {
		t, e := scopeLabels(u.Tenant, u.Environment)
		upgrade.WithLabelValues(t, e, u.Product, u.Constraint, u.UpgradeTo).Set(1)
		unfixed.WithLabelValues(t, e, u.Product).Set(float64(u.Unfixed))
		imageOnly.WithLabelValues(t, e, u.Product).Set(float64(u.ImageOnly))
	}
	gauge("images_unmatched", "Images Trivy scanned that belong to no product in the stack.").WithLabelValues().Set(float64(len(rep.UnmatchedImages)))
	gauge("image_findings_filtered", "Image-only findings below the Trivy filter in the last run.").WithLabelValues().Set(float64(rep.ImageFiltered))
	gauge("kernel_findings_filtered", "Kernel fixes of the nodes' distribution neither KEV-listed nor likely exploited, in the last run.").WithLabelValues().Set(float64(rep.KernelFiltered))

	single := gauge("findings_single_source", "Findings in the last run only one of cvelist and NVD found, by that source (set when both run).", "source")
	for s, n := range rep.SingleSource {
		single.WithLabelValues(s).Set(float64(n))
	}
	srcF := gauge("source_findings", "Raw findings returned per source in the last run.", "source")
	srcE := gauge("source_errors", "Failed requests (product/source pairs) per source in the last run.", "source")
	for _, s := range rep.Sources {
		srcF.WithLabelValues(s.Name).Set(float64(s.Findings))
		srcE.WithLabelValues(s.Name).Set(float64(s.Errors))
	}
	gauge("warnings", "Warnings in the last report.").WithLabelValues().Set(float64(len(rep.Warnings)))
	return &Metrics{Registry: reg}
}

// Push replaces the job's metric group on the Pushgateway (PUT). Health-only
// metrics are added instead (POST): they replace their own families and
// leave the open findings of the last report in place.
func Push(ctx context.Context, cfg config.Metrics, hc *http.Client, reg *Metrics) error {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout.D())
	defer cancel()
	p := push.New(cfg.PushgatewayURL, cfg.Job).Gatherer(reg).Client(hc)
	for _, k := range config.SortedKeys(cfg.Grouping) {
		p = p.Grouping(k, cfg.Grouping[k])
	}
	if reg.HealthOnly {
		return p.AddContext(ctx)
	}
	return p.PushContext(ctx)
}

// WriteFile writes the metrics in the Prometheus text format (atomically),
// e.g. for node-exporter's textfile collector.
func WriteFile(path string, reg prometheus.Gatherer) error {
	return prometheus.WriteToTextfile(path, reg)
}

// advisoryURLs returns the first NVD and the first GitHub advisory page.
func advisoryURLs(as []report.Advisory) (nvd, github string) {
	for _, a := range as {
		switch {
		case a.Source == "NVD" && nvd == "":
			nvd = a.URL
		case a.Source == "GitHub" && github == "":
			github = a.URL
		}
	}
	return nvd, github
}

func cvss(v float64) string {
	if v == 0 {
		return ""
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// imageLabel says how Trivy is involved: "confirmed" (advisory and image),
// "only" (image only) or "" (advisory only).
func imageLabel(inImage, imageOnly bool) string {
	switch {
	case imageOnly:
		return "only"
	case inImage:
		return "confirmed"
	}
	return ""
}

// scopeLabels are the tenant and environment labels; products resolved
// without a scope (tests, single commands) count as the local stack.
func scopeLabels(tenant, env string) (string, string) {
	if tenant == "" {
		tenant = config.DefaultTenant
	}
	if env == "" {
		env = config.DefaultEnvironment
	}
	return tenant, env
}

func cmpTime(t, def time.Time) time.Time {
	if t.IsZero() {
		return def
	}
	return t
}
