package pipeline

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/triage"
)

// AuditFinding is one advisory that affects, or may affect, a product.
type AuditFinding struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases,omitempty"`
	Title    string   `json:"title"`
	Match    string   `json:"match"` // affected | unknown (depends on the exact version)
	Detail   string   `json:"match_detail"`
	Priority string   `json:"priority"` // rule-based
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss,omitempty"`
	KEV      bool     `json:"kev"`
	EPSS     float64  `json:"epss,omitempty"`
	Fixed    []string `json:"fixed,omitempty"`
	Link     string   `json:"link,omitempty"`
	// Advisories are the NVD and GitHub pages for the finding's IDs.
	Advisories []report.Advisory `json:"advisories,omitempty"`
	// Versions lists which deployed versions it affects, for products
	// deployed in several versions ("26.7.0 || 20.0.3").
	Versions []string `json:"versions,omitempty"`
}

// VersionCount is the audit result for one of several deployed versions.
type VersionCount struct {
	Version  string `json:"version"`
	Affected int    `json:"affected"`
	Unknown  int    `json:"unknown"`
}

// AuditProduct is the full-history result for one product.
type AuditProduct struct {
	Product        string         `json:"product"`
	Tenant         string         `json:"tenant,omitempty"`
	Environment    string         `json:"environment,omitempty"`
	Scope          string         `json:"-"` // "tenant/environment" when stack.yaml has tenants
	Constraint     string         `json:"constraint"`
	Checked        int            `json:"checked"`
	Affected       int            `json:"affected"`
	Unknown        int            `json:"unknown"`
	NotAffected    int            `json:"not_affected"`
	NoVersionData  int            `json:"no_version_data"` // only counted: says nothing about our version
	BelowThreshold int            `json:"below_threshold"`
	Complete       bool           `json:"complete"` // false: a source failed
	ByVersion      []VersionCount `json:"by_version,omitempty"`
	Findings       []AuditFinding `json:"findings"`
}

// Audit checks products against their full advisory history: what affects
// the given versions, and what depends on the exact version. It reads no
// state and changes nothing; priorities are rule-based (no LLM).
// Kernel fixes are filtered like in a run (kernel: sources.os).
func Audit(ctx context.Context, srcs []sources.Source, enr []sources.Enricher, products []catalog.Product, links report.AdvisoryLinks, kernel config.OSSource, concurrency int, log *slog.Logger) ([]AuditProduct, []string, error) {
	col, err := Collect(ctx, srcs, products, time.Time{}, concurrency, log)
	if err != nil {
		return nil, nil, err
	}
	warnings := col.Warnings
	fs := finding.Dedup(col.Findings)
	cleanFixed(fs)
	for _, e := range enr {
		if err := e.Enrich(ctx, fs); err != nil {
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			warnings = append(warnings, e.Name()+" (enrichment): "+err.Error())
		}
	}
	fs, _ = filterKernel(fs, kernel)
	byName := map[string]catalog.Product{}
	results := map[string]*AuditProduct{}
	multi := slices.ContainsFunc(products, func(p catalog.Product) bool { return p.Scope.Remote })
	for _, p := range products {
		byName[p.Key()] = p
		r := &AuditProduct{Product: p.Name, Tenant: p.Scope.Tenant, Environment: p.Scope.Environment,
			Constraint: p.Constraint.String(), Complete: !col.Failed[p.Key()], Findings: []AuditFinding{}}
		if multi {
			r.Scope = p.Scope.String()
		}
		if alts := p.Constraint.Alternatives(); len(alts) > 1 {
			for _, a := range alts {
				r.ByVersion = append(r.ByVersion, VersionCount{Version: a.String()})
			}
		}
		results[p.Key()] = r
	}
	MatchAll(fs, byName)
	for _, f := range fs {
		p, r := byName[f.Product], results[f.Product]
		r.Checked++
		noData := !f.HasVersionData()
		switch {
		case f.CVSS > 0 && f.CVSS < p.MinCVSS && !f.KEV:
			r.BelowThreshold++
			continue
		case f.Match == string(match.NotAffected):
			r.NotAffected++
			continue
		case f.Match == string(match.Unknown) && (noData || p.Constraint.Any()):
			r.NoVersionData++
			continue
		case f.Match == string(match.Affected):
			r.Affected++
		default:
			r.Unknown++
		}
		af := AuditFinding{
			ID: f.ID, Aliases: f.Aliases, Title: f.Title, Match: f.Match, Detail: f.MatchDetail,
			Priority: triage.Deterministic(triage.Item{Finding: f, Product: p}).Priority,
			Severity: f.Severity, CVSS: f.CVSS, KEV: f.KEV, EPSS: f.EPSS, Fixed: f.Fixed,
		}
		if len(f.References) > 0 {
			af.Link = f.References[0]
		}
		af.Advisories = links.For(f.IDs(), f.References...)
		for i, alt := range p.Constraint.Alternatives() {
			if len(r.ByVersion) == 0 {
				break
			}
			switch match.Match(alt, f.Affected, f.AffectedVersions).Status {
			case match.Affected:
				r.ByVersion[i].Affected++
				af.Versions = append(af.Versions, alt.String())
			case match.Unknown:
				r.ByVersion[i].Unknown++
				af.Versions = append(af.Versions, alt.String()+"?")
			}
		}
		r.Findings = append(r.Findings, af)
	}
	out := make([]AuditProduct, 0, len(products))
	for _, p := range products {
		r := results[p.Key()]
		slices.SortStableFunc(r.Findings, func(a, b AuditFinding) int {
			return cmp.Or(cmp.Compare(a.Match, b.Match), cmp.Compare(a.Priority, b.Priority), boolFirst(a.KEV, b.KEV),
				cmp.Compare(b.CVSS, a.CVSS), cmp.Compare(a.ID, b.ID))
		})
		out = append(out, *r)
	}
	slices.Sort(warnings)
	return out, warnings, nil
}

func boolFirst(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
}
