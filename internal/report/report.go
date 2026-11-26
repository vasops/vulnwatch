// Package report builds the output-independent report model.
package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/triage"
)

// Modes.
const (
	ModeRun       = "run"
	ModeDryRun    = "dry-run"
	ModeBootstrap = "bootstrap"
)

// PriorityLabels describes each priority in plain words.
var PriorityLabels = map[string]string{
	"P1": "Act today",
	"P2": "This week",
	"P3": "Next maintenance",
	"P4": "Informational",
}

// Report is rendered by every output.
type Report struct {
	Mode        string          `json:"mode"`
	GeneratedAt time.Time       `json:"generated_at"`
	Since       time.Time       `json:"since"`
	Until       time.Time       `json:"until"`
	Products    []ProductInfo   `json:"products"`
	Counts      []PriorityCount `json:"counts"`
	Groups      []PriorityGroup `json:"groups"`
	// NotRelevant counts findings triaged as relevant: no (collapsed).
	NotRelevant int `json:"not_relevant"`
	// BelowThreshold counts findings dropped by min_cvss (never KEV-listed ones).
	BelowThreshold int `json:"below_threshold"`
	// Unchanged counts findings already reported without material change.
	Unchanged int `json:"unchanged"`
	// Baselines lists products whose full advisory history was checked in
	// this run (new product, version or sources changed, or bootstrap).
	Baselines []BaselineSummary `json:"baselines,omitempty"`
	// Open lists findings reported in earlier runs that still affect the
	// versions in stack.yaml; they stay here until the product is upgraded.
	Open []OpenItem `json:"open"`
	// OpenUnknown counts earlier findings that can't be tracked as open:
	// products tracked with "*", or findings without version data whose
	// product version changed since (or that predate version tracking).
	OpenUnknown int `json:"open_unknown"`
	// Sources counts raw findings and failures per source in this run.
	Sources  []SourceStat `json:"sources"`
	Warnings []string     `json:"warnings"`
	// ImageFiltered counts image findings (Trivy, no advisory for the
	// product) below the Trivy filter: no fixed package, or not KEV-listed,
	// likely exploited or severe enough.
	ImageFiltered int `json:"image_filtered,omitempty"`
	// UnmatchedImages are scanned images no product in the stack claims
	// (catalog images); their findings are not reported.
	UnmatchedImages []string `json:"unmatched_images,omitempty"`
	// KernelFiltered counts kernel fixes of the nodes' distribution that are
	// neither KEV-listed nor likely exploited (sources.os).
	KernelFiltered int `json:"kernel_filtered,omitempty"`
	// SingleSource counts, by source, the findings only cvelist or only NVD
	// found, when both run.
	SingleSource map[string]int `json:"single_source,omitempty"`
	// TriageFailures counts the Claude triage calls (batches) that failed:
	// API error, or invalid output after the retry. Their findings got the
	// rule-based priority. Run-wide: every route keeps it.
	TriageFailures int `json:"triage_failures,omitempty"`
	// TriageUntriaged counts the findings those failures left with the
	// rule-based priority (asked again in a later run); TriageFailure says
	// why the first batch failed.
	TriageUntriaged int    `json:"triage_untriaged,omitempty"`
	TriageFailure   string `json:"triage_failure,omitempty"`
	// TriageUsage is what the Claude triage requests of the run used; absent
	// when triage made no request.
	TriageUsage *TriageUsage `json:"triage_usage,omitempty"`
	// MultiTenant is set when stack.yaml has tenants: outputs then name
	// each product's tenant and environment (Scope).
	MultiTenant bool `json:"multi_tenant,omitempty"`
	// Scopes are the local stack and every tenant environment in the run.
	Scopes []ScopeInfo `json:"scopes,omitempty"`
	// Weekly is set when the run sends the weekly report.
	Weekly *Weekly `json:"weekly,omitempty"`
}

// TriageUsage is the requests and tokens of the Claude triage in one run.
type TriageUsage struct {
	Model                    string `json:"model"`
	Requests                 int64  `json:"requests"`
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
}

// ScopeInfo is one tenant environment (or the local stack) in the run.
type ScopeInfo struct {
	Tenant      string            `json:"tenant"`
	Environment string            `json:"environment"`
	Remote      bool              `json:"remote,omitempty"` // a tenant's, not the cluster vulnwatch runs in
	Slack       config.SlackRoute `json:"-"`
}

// String is "tenant/environment".
func (s ScopeInfo) String() string { return s.Tenant + "/" + s.Environment }

// SourceStat is one source's yield in a run.
type SourceStat struct {
	Name     string `json:"name"`
	Findings int    `json:"findings"`
	Errors   int    `json:"errors"`
}

// OpenItem is a previously reported finding that still affects us.
type OpenItem struct {
	ID            string     `json:"id"`
	Product       string     `json:"product"`
	Tenant        string     `json:"tenant,omitempty"`
	Environment   string     `json:"environment,omitempty"`
	Scope         string     `json:"-"` // "tenant/environment" when stack.yaml has tenants (outputs name it)
	Constraint    string     `json:"constraint"`
	Title         string     `json:"title"`
	Fixed         []string   `json:"fixed,omitempty"`
	CVSS          float64    `json:"cvss,omitempty"`
	Severity      string     `json:"severity"`
	KEV           bool       `json:"kev"`
	EPSS          float64    `json:"epss,omitempty"`
	Match         string     `json:"match"`                     // affected, or unknown when only part of the constraint is affected
	NoVersionData bool       `json:"no_version_data,omitempty"` // open until the product's version changes
	Priority      string     `json:"priority"`
	FirstReported time.Time  `json:"first_reported"`
	DaysOpen      int        `json:"days_open"`
	Link          string     `json:"link,omitempty"`
	Aliases       []string   `json:"aliases,omitempty"`
	Advisories    []Advisory `json:"advisories,omitempty"` // NVD and GitHub pages
	References    []string   `json:"-"`                    // the finding's links, for Advisories
	FirstSeen     bool       `json:"first_seen,omitempty"` // learned in this run (full-history check)
	// Summary and Action are Claude's explanation and next step, when it
	// triaged the finding.
	Summary string `json:"summary,omitempty"`
	Action  string `json:"action,omitempty"`
	// Packages are the vulnerable packages Trivy still finds running.
	Packages  []finding.Package `json:"packages,omitempty"`
	ImageOnly bool              `json:"image_only,omitempty"` // only Trivy reports it, no advisory for the product
}

type ProductInfo struct {
	Name        string `json:"name"`
	Tenant      string `json:"tenant,omitempty"`
	Environment string `json:"environment,omitempty"`
	Scope       string `json:"-"`
	Constraint  string `json:"constraint"`
	Exposure    string `json:"exposure"`
	Criticality string `json:"criticality"`
}

type PriorityCount struct {
	Priority string `json:"priority"`
	Count    int    `json:"count"`
}

type PriorityGroup struct {
	Priority string         `json:"priority"`
	Label    string         `json:"label"`
	Products []ProductGroup `json:"products"`
}

type ProductGroup struct {
	Product     string `json:"product"`
	Tenant      string `json:"tenant,omitempty"`
	Environment string `json:"environment,omitempty"`
	Scope       string `json:"-"`
	Constraint  string `json:"constraint"`
	Items       []Item `json:"items"`
}

// Reasons for a full-history check.
const (
	BaselineNew            = "new"
	BaselineVersionChanged = "version changed"
	BaselineSourcesChanged = "sources changed"
	BaselineMatching       = "matching updated" // matchingVersion bumped: stored findings re-read
	BaselineBootstrap      = "bootstrap"
)

// BaselineSummary is one product whose full advisory history was checked.
type BaselineSummary struct {
	Product     string `json:"product"`
	Tenant      string `json:"tenant,omitempty"`
	Environment string `json:"environment,omitempty"`
	Scope       string `json:"-"` // "tenant/environment" when stack.yaml has tenants (outputs name it)
	Constraint  string `json:"constraint"`
	Reason      string `json:"reason"`
	Checked     int    `json:"checked"`         // advisories in the product's history
	Affected    int    `json:"affected"`        // affect every deployed version
	Unknown     int    `json:"unknown"`         // depend on the exact version (partial overlap)
	NoData      int    `json:"no_version_data"` // no version data: only counted
	KEV         int    `json:"kev"`             // affected or unknown, and exploited in the wild
	Complete    bool   `json:"complete"`        // false: a source failed; checked again next run
}

// Item is one finding as presented in reports.
type Item struct {
	ID             string     `json:"id"`
	Aliases        []string   `json:"aliases,omitempty"`
	Product        string     `json:"product"`
	Tenant         string     `json:"tenant,omitempty"`
	Environment    string     `json:"environment,omitempty"`
	Scope          string     `json:"-"` // "tenant/environment" when stack.yaml has tenants (outputs name it)
	Constraint     string     `json:"constraint"`
	Title          string     `json:"title"`
	Fixed          []string   `json:"fixed,omitempty"`
	CVSS           float64    `json:"cvss,omitempty"`
	Severity       string     `json:"severity"`
	KEV            bool       `json:"kev"`
	EPSS           float64    `json:"epss,omitempty"`
	EPSSPercentile float64    `json:"epss_percentile,omitempty"`
	Match          string     `json:"match"`
	NoVersionData  bool       `json:"no_version_data,omitempty"` // the sources give no affected versions
	Relevant       string     `json:"relevant"`
	Priority       string     `json:"priority"`
	Summary        string     `json:"summary"`
	Reasoning      string     `json:"reasoning"`
	Action         string     `json:"action"`
	Triaged        bool       `json:"triaged"`
	TriageNote     string     `json:"triage_note,omitempty"`
	Change         string     `json:"change"`                  // "new" or the material changes
	FirstReported  time.Time  `json:"first_reported,omitzero"` // when vulnwatch first reported it
	Advisories     []Advisory `json:"advisories,omitempty"`    // NVD and GitHub pages
	Links          []string   `json:"links,omitempty"`         // other references
	// Packages are vulnerable packages Trivy found in the running images:
	// with an advisory they confirm the vulnerable code runs (ImageOnly
	// false), without one they are the whole finding (ImageOnly true).
	Packages  []finding.Package `json:"packages,omitempty"`
	ImageOnly bool              `json:"image_only,omitempty"`
	// Red Hat's rating and statement (sources.redhat).
	RedHatSeverity  string `json:"redhat_severity,omitempty"`
	RedHatStatement string `json:"redhat_statement,omitempty"`
}

// Entry is one finding with everything needed to present it.
type Entry struct {
	Finding       finding.Finding
	Product       catalog.Product
	Triage        triage.Result
	Change        string
	FirstReported time.Time // zero: this run
}

// Meta carries the run-level facts for Build.
type Meta struct {
	Mode            string
	GeneratedAt     time.Time
	Since, Until    time.Time
	Products        []catalog.Product
	BelowThreshold  int
	Unchanged       int
	Warnings        []string
	Open            []OpenItem
	OpenUnknown     int
	Sources         []SourceStat
	Baselines       []BaselineSummary
	Links           AdvisoryLinks
	ImageFiltered   int
	UnmatchedImages []string
	KernelFiltered  int
	SingleSource    map[string]int
	TriageFailures  int
	TriageUntriaged int
	TriageFailure   string
	TriageUsage     *TriageUsage
	// Weekly, when set, asks for the weekly report: its window (From,
	// Until) and closed findings; Build fills in the rest.
	Weekly *Weekly
}

// Build assembles the report: grouped by priority, then product; relevant:
// no findings collapse into a count.
func Build(m Meta, entries []Entry) Report {
	r := Report{
		Mode:           m.Mode,
		GeneratedAt:    m.GeneratedAt.UTC(),
		Since:          m.Since.UTC(),
		Until:          m.Until.UTC(),
		BelowThreshold: m.BelowThreshold,
		Unchanged:      m.Unchanged,
		Open:           append([]OpenItem{}, m.Open...),
		OpenUnknown:    m.OpenUnknown,
		Sources:        append([]SourceStat{}, m.Sources...),
		Warnings:       append([]string{}, m.Warnings...),

		ImageFiltered:   m.ImageFiltered,
		UnmatchedImages: m.UnmatchedImages,
		KernelFiltered:  m.KernelFiltered,
		SingleSource:    m.SingleSource,
		TriageFailures:  m.TriageFailures,
		TriageUntriaged: m.TriageUntriaged,
		TriageFailure:   m.TriageFailure,
		TriageUsage:     m.TriageUsage,
	}
	seen := map[config.Scope]bool{}
	for _, p := range m.Products {
		sc := p.Scope
		sc.Slack = config.SlackRoute{}
		if seen[sc] {
			continue
		}
		seen[sc] = true
		r.Scopes = append(r.Scopes, ScopeInfo{Tenant: p.Scope.Tenant, Environment: p.Scope.Environment, Remote: p.Scope.Remote, Slack: p.Scope.Slack})
		r.MultiTenant = r.MultiTenant || p.Scope.Remote
	}
	scope := func(tenant, env string) string {
		if !r.MultiTenant {
			return ""
		}
		return tenant + "/" + env
	}
	for i := range r.Open {
		r.Open[i].Scope = scope(r.Open[i].Tenant, r.Open[i].Environment)
		r.Open[i].Advisories = m.Links.For(append([]string{r.Open[i].ID}, r.Open[i].Aliases...), r.Open[i].References...)
		r.Open[i].DaysOpen = int(r.GeneratedAt.Sub(r.Open[i].FirstReported).Hours() / 24)
	}
	slices.SortStableFunc(r.Open, func(a, b OpenItem) int {
		return cmp.Or(
			cmp.Compare(a.Priority, b.Priority),
			boolCmp(b.KEV, a.KEV),
			cmp.Compare(b.CVSS, a.CVSS),
			cmp.Compare(a.Tenant, b.Tenant),
			cmp.Compare(a.Environment, b.Environment),
			cmp.Compare(a.Product, b.Product),
			cmp.Compare(a.ID, b.ID),
		)
	})
	for _, p := range m.Products {
		r.Products = append(r.Products, ProductInfo{
			Name: p.Name, Tenant: p.Scope.Tenant, Environment: p.Scope.Environment, Scope: scope(p.Scope.Tenant, p.Scope.Environment),
			Constraint: p.Constraint.String(), Exposure: p.Exposure, Criticality: p.Criticality,
		})
	}
	r.Baselines = append([]BaselineSummary{}, m.Baselines...)
	for i := range r.Baselines {
		r.Baselines[i].Scope = scope(r.Baselines[i].Tenant, r.Baselines[i].Environment)
	}
	slices.SortStableFunc(r.Baselines, func(a, b BaselineSummary) int {
		return cmp.Or(cmp.Compare(b.KEV, a.KEV), cmp.Compare(b.Affected, a.Affected), cmp.Compare(b.Unknown, a.Unknown), cmp.Compare(a.Product, b.Product))
	})
	var items []Item
	for _, e := range entries {
		if e.Triage.Relevant == "no" {
			r.NotRelevant++
			continue
		}
		it := toItem(e, m.Links)
		it.Scope = scope(it.Tenant, it.Environment)
		if it.FirstReported.IsZero() {
			it.FirstReported = r.GeneratedAt
		}
		items = append(items, it)
	}
	slices.SortStableFunc(items, func(a, b Item) int {
		return cmp.Or(
			cmp.Compare(a.Priority, b.Priority),
			cmp.Compare(a.Tenant, b.Tenant),
			cmp.Compare(a.Environment, b.Environment),
			cmp.Compare(a.Product, b.Product),
			boolCmp(b.KEV, a.KEV),
			cmp.Compare(b.CVSS, a.CVSS),
			cmp.Compare(a.ID, b.ID),
		)
	})
	for _, p := range triage.Priorities {
		n := 0
		for _, it := range items {
			if it.Priority == p {
				n++
			}
		}
		r.Counts = append(r.Counts, PriorityCount{p, n})
	}
	for _, it := range items {
		n := len(r.Groups)
		if n == 0 || r.Groups[n-1].Priority != it.Priority {
			r.Groups = append(r.Groups, PriorityGroup{Priority: it.Priority, Label: PriorityLabels[it.Priority]})
			n++
		}
		g := &r.Groups[n-1]
		pn := len(g.Products)
		if pn == 0 || g.Products[pn-1].Product != it.Product || g.Products[pn-1].Tenant != it.Tenant || g.Products[pn-1].Environment != it.Environment {
			g.Products = append(g.Products, ProductGroup{
				Product: it.Product, Tenant: it.Tenant, Environment: it.Environment, Scope: it.Scope, Constraint: it.Constraint,
			})
			pn++
		}
		g.Products[pn-1].Items = append(g.Products[pn-1].Items, it)
	}
	if w := m.Weekly; w != nil {
		closed := slices.Clone(w.Closed)
		for i := range closed {
			closed[i].Scope = scope(closed[i].Tenant, closed[i].Environment)
			closed[i].Advisories = m.Links.For(append([]string{closed[i].ID}, closed[i].Aliases...), closed[i].References...)
		}
		slices.SortStableFunc(closed, func(a, b ClosedItem) int {
			return cmp.Or(cmp.Compare(rank(a.Priority), rank(b.Priority)), cmp.Compare(a.Tenant, b.Tenant),
				cmp.Compare(a.Environment, b.Environment), cmp.Compare(a.Product, b.Product), cmp.Compare(a.ID, b.ID))
		})
		r.Weekly = r.weekly(w.From, w.Until, closed)
	}
	return r
}

// BaselineSplit separates checked products with something affecting (or
// possibly affecting) them, or an incomplete check, from clean ones.
func (r Report) BaselineSplit() (found, clean []BaselineSummary) {
	for _, b := range r.Baselines {
		if b.Affected+b.Unknown > 0 || !b.Complete {
			found = append(found, b)
			continue
		}
		clean = append(clean, b)
	}
	return found, clean
}

// BaselinesFound and BaselinesClean are BaselineSplit for templates.
func (r Report) BaselinesFound() []BaselineSummary { f, _ := r.BaselineSplit(); return f }
func (r Report) BaselinesClean() []BaselineSummary { _, c := r.BaselineSplit(); return c }

// Facts describes a baseline in one line, e.g. "412 advisories checked ·
// 3 affected · 2 depend on the exact version · 1 exploited (KEV)".
func (b BaselineSummary) Facts() string {
	parts := []string{fmt.Sprintf("%d advisories checked", b.Checked)}
	if b.Affected > 0 {
		parts = append(parts, fmt.Sprintf("%d affected", b.Affected))
	}
	if b.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d depend on the exact version", b.Unknown))
	}
	if b.NoData > 0 {
		parts = append(parts, fmt.Sprintf("%d without version data", b.NoData))
	}
	if b.KEV > 0 {
		parts = append(parts, fmt.Sprintf("%d exploited (KEV)", b.KEV))
	}
	if !b.Complete {
		parts = append(parts, "incomplete: a source failed, checked again next run")
	}
	return strings.Join(parts, " · ")
}

// Names joins the products of the given baselines.
func Names(bs []BaselineSummary) string {
	names := make([]string, len(bs))
	for i, b := range bs {
		names[i] = Named(b.Scope, b.Product)
	}
	return strings.Join(names, ", ")
}

// Named is how outputs name a product: "acme/prod keycloak" when stack.yaml
// has tenants (scope set), else "keycloak".
func Named(scope, product string) string {
	if scope == "" {
		return product
	}
	return scope + " " + product
}

// ForScopes returns the report limited to the scopes keep accepts: the new
// findings, still-open ones, products and full-history checks (counts
// recomputed). Run-wide facts (sources, warnings, filter counts) are kept
// only with keepRunWide.
func (r Report) ForScopes(keep func(ScopeInfo) bool, keepRunWide bool) Report {
	in := func(tenant, env string) bool {
		for _, s := range r.Scopes {
			if s.Tenant == tenant && s.Environment == env {
				return keep(s)
			}
		}
		return false
	}
	out := r
	out.Scopes = slices.DeleteFunc(slices.Clone(r.Scopes), func(s ScopeInfo) bool { return !keep(s) })
	out.Products = slices.DeleteFunc(slices.Clone(r.Products), func(p ProductInfo) bool { return !in(p.Tenant, p.Environment) })
	out.Open = slices.DeleteFunc(slices.Clone(r.Open), func(it OpenItem) bool { return !in(it.Tenant, it.Environment) })
	out.Baselines = slices.DeleteFunc(slices.Clone(r.Baselines), func(b BaselineSummary) bool { return !in(b.Tenant, b.Environment) })
	out.Groups = nil
	for _, g := range r.Groups {
		ng := PriorityGroup{Priority: g.Priority, Label: g.Label}
		for _, pg := range g.Products {
			if in(pg.Tenant, pg.Environment) {
				ng.Products = append(ng.Products, pg)
			}
		}
		if len(ng.Products) > 0 {
			out.Groups = append(out.Groups, ng)
		}
	}
	out.Counts = nil
	for _, c := range r.Counts {
		n := 0
		for _, it := range out.Items() {
			if it.Priority == c.Priority {
				n++
			}
		}
		out.Counts = append(out.Counts, PriorityCount{c.Priority, n})
	}
	if r.Weekly != nil {
		known := func(tenant, env string) bool {
			return slices.ContainsFunc(r.Scopes, func(s ScopeInfo) bool { return s.Tenant == tenant && s.Environment == env })
		}
		// A closed finding of an environment no longer in the stack has no
		// route of its own: the default one (keepRunWide) gets it.
		closed := slices.DeleteFunc(slices.Clone(r.Weekly.Closed), func(it ClosedItem) bool {
			return !in(it.Tenant, it.Environment) && (!keepRunWide || known(it.Tenant, it.Environment))
		})
		out.Weekly = out.weekly(r.Weekly.From, r.Weekly.Until, closed)
	}
	if !keepRunWide {
		out.Warnings, out.Sources, out.UnmatchedImages = nil, nil, nil
		out.NotRelevant, out.BelowThreshold, out.Unchanged, out.OpenUnknown = 0, 0, 0, 0
		out.ImageFiltered, out.KernelFiltered = 0, 0
	}
	return out
}

// Total returns the number of new or updated findings.
func (r Report) Total() int {
	n := 0
	for _, c := range r.Counts {
		n += c.Count
	}
	return n
}

// FailedSources names the sources and enrichers that failed in this run,
// sorted, read from the warnings ("<source>/<product>: …" or "<source>
// (enrichment): …"). Any makes the run incomplete. Names only: the
// warnings themselves carry internal detail (URLs, errors).
func (r Report) FailedSources() []string {
	var out []string
	for _, w := range r.Warnings {
		name, _, _ := strings.Cut(w, "/")
		name, _, _ = strings.Cut(name, " ")
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Label is how outputs name an advisory: its ID, or its title when the ID
// is a URL (feed items without CVE or GHSA IDs).
func Label(id, title string) string {
	if !strings.HasPrefix(id, "http://") && !strings.HasPrefix(id, "https://") {
		return id
	}
	if title == "" {
		return "advisory"
	}
	if r := []rune(title); len(r) > 70 {
		return string(r[:69]) + "…"
	}
	return title
}

// OpenCounts returns the number of still-open items per priority.
func (r Report) OpenCounts() []PriorityCount {
	var out []PriorityCount
	for _, p := range triage.Priorities {
		n := 0
		for _, it := range r.Open {
			if it.Priority == p {
				n++
			}
		}
		out = append(out, PriorityCount{p, n})
	}
	return out
}

// CurrentOpenCounts returns, per priority, the findings currently affecting
// the stack: listed in this run (new or updated) plus still open from
// earlier runs. It is the definition of the findings_open metric, so the
// Slack summary and Grafana agree.
func (r Report) CurrentOpenCounts() []PriorityCount {
	out := r.OpenCounts()
	for _, it := range r.Items() {
		for i := range out {
			if out[i].Priority == it.Priority {
				out[i].Count++
			}
		}
	}
	return out
}

// Empty reports whether there is nothing new to report.
func (r Report) Empty() bool { return r.Total() == 0 }

// Items returns all listed items in report order.
func (r Report) Items() []Item {
	var out []Item
	for _, g := range r.Groups {
		for _, p := range g.Products {
			out = append(out, p.Items...)
		}
	}
	return out
}

func toItem(e Entry, links AdvisoryLinks) Item {
	f := e.Finding
	adv := links.For(f.IDs(), f.References...)
	return Item{
		ID:             f.ID,
		Aliases:        f.Aliases,
		Product:        e.Product.Name,
		Tenant:         e.Product.Scope.Tenant,
		Environment:    e.Product.Scope.Environment,
		Constraint:     e.Product.Constraint.String(),
		Title:          f.Title,
		Fixed:          f.Fixed,
		CVSS:           f.CVSS,
		Severity:       f.Severity,
		KEV:            f.KEV,
		EPSS:           f.EPSS,
		EPSSPercentile: f.EPSSPercentile,
		Match:          f.Match,
		NoVersionData:  !f.HasVersionData() && !f.InImage(),
		Relevant:       e.Triage.Relevant,
		Priority:       e.Triage.Priority,
		Summary:        e.Triage.Summary,
		Reasoning:      e.Triage.Reasoning,
		Action:         e.Triage.Action,
		Triaged:        e.Triage.Triaged(),
		TriageNote:     e.Triage.Note,
		Change:         cmp.Or(e.Change, "new"),
		FirstReported:  e.FirstReported,
		Advisories:     adv,
		Links:          otherLinks(f.References, adv, 3),
		Packages:       f.Packages,
		ImageOnly:      f.ImageOnly(),
		// Red Hat (sources.redhat).
		RedHatSeverity:  f.RedHatSeverity,
		RedHatStatement: f.RedHatStatement,
	}
}

func boolCmp(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
