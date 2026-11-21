// Package ghsa fetches repository-level GitHub security advisories.
//
// API: GET {base_url}/repos/{owner}/{repo}/security-advisories, cursor
// pagination via the Link header. Package-level GHSA data arrives via OSV.
package ghsa

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/sources"
)

const Name = "ghsa"

type Source struct {
	cfg      config.GHSASource
	client   *httpx.Client
	token    string
	log      *slog.Logger
	warnOnce sync.Once
}

func New(cfg config.GHSASource, client *httpx.Client, getenv func(string) string, log *slog.Logger) *Source {
	return &Source{cfg: cfg, client: client, token: getenv(cfg.TokenEnv), log: log}
}

func (s *Source) Name() string { return Name }

type cvssScore struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

type advisory struct {
	GHSAID      string  `json:"ghsa_id"`
	CVEID       *string `json:"cve_id"`
	HTMLURL     string  `json:"html_url"`
	Summary     string  `json:"summary"`
	Description string  `json:"description"`
	Severity    *string `json:"severity"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	CVSS           *cvssScore `json:"cvss"`
	CVSSSeverities struct {
		V3 *cvssScore `json:"cvss_v3"`
		V4 *cvssScore `json:"cvss_v4"`
	} `json:"cvss_severities"`
	Vulnerabilities []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		PatchedVersions        string `json:"patched_versions"`
	} `json:"vulnerabilities"`
	PublishedAt *time.Time `json:"published_at"`
	UpdatedAt   *time.Time `json:"updated_at"`
	WithdrawnAt *time.Time `json:"withdrawn_at"`
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	if len(sel.Entry.GHSA) == 0 {
		return nil, nil
	}
	headers := map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": s.cfg.APIVersion,
	}
	if s.token != "" {
		headers["Authorization"] = "Bearer " + s.token
	} else {
		s.warnOnce.Do(func() {
			s.log.Warn("no GitHub token set; using unauthenticated API (60 requests/hour)", "source", Name, "env", s.cfg.TokenEnv)
		})
	}
	var out []finding.Finding
	for _, repo := range sel.Entry.GHSA {
		url := fmt.Sprintf("%s/repos/%s/security-advisories?state=published&sort=updated&direction=desc&per_page=%d",
			strings.TrimRight(s.cfg.BaseURL, "/"), repo, max(s.cfg.PerPage, 1))
		for url != "" {
			var page []advisory
			h, err := s.client.GetJSON(ctx, url, headers, &page)
			if err != nil {
				return out, fmt.Errorf("%s: %w", repo, err)
			}
			url = ""
			older := false
			for _, a := range page {
				if a.UpdatedAt != nil && a.UpdatedAt.Before(since) {
					older = true // sorted by updated desc: the rest is older too
					break
				}
				if a.WithdrawnAt != nil {
					continue
				}
				out = append(out, toFinding(sel.Product, a))
			}
			if !older {
				if m := linkNext.FindStringSubmatch(h.Get("Link")); m != nil {
					url = m[1]
				}
			}
		}
	}
	return out, nil
}

func toFinding(product string, a advisory) finding.Finding {
	f := finding.Finding{
		ID:          a.GHSAID,
		Product:     product,
		Title:       a.Summary,
		Description: sources.Truncate(a.Description, 4000),
		Sources:     []string{Name},
		References:  []string{a.HTMLURL},
	}
	if a.CVEID != nil {
		f.Aliases = append(f.Aliases, *a.CVEID)
	}
	for _, id := range a.Identifiers {
		f.Aliases = append(f.Aliases, id.Value)
	}
	// Some advisories leave cve_id empty and name the CVE only in the text.
	// One CVE named is the advisory's own; several may be related ones.
	if !slices.ContainsFunc(f.Aliases, isCVE) {
		if cves := finding.ExtractCVEs(a.Summary + "\n" + a.Description); len(cves) == 1 {
			f.Aliases = append(f.Aliases, cves[0])
		}
	}
	for _, c := range []*cvssScore{a.CVSSSeverities.V3, a.CVSSSeverities.V4, a.CVSS} {
		if c != nil && c.Score != nil && *c.Score > 0 {
			f.CVSS = *c.Score
			if c.VectorString != nil {
				f.CVSSVector = *c.VectorString
			}
			break
		}
	}
	if a.Severity != nil {
		f.Severity = finding.NormalizeSeverity(*a.Severity)
	}
	var (
		names []string                       // packages with version data, in order
		byPkg = map[string][]finding.Range{} // their ranges
		fixes = map[string][]string{}        // every patched version per package
	)
	// One entry per release line is common ("<= 3.7.0" patched "3.7.1",
	// "<= 3.6.13" patched "3.6.14"): each entry's range is split by every
	// fix of the package, so the 3.7 entry doesn't cover a fixed 3.6.14.
	for _, v := range a.Vulnerabilities {
		name := packageName(v.Package.Ecosystem, v.Package.Name)
		fixes[name] = append(fixes[name], sources.SplitVersions(v.PatchedVersions)...)
	}
	for _, v := range a.Vulnerabilities {
		patched := sources.SplitVersions(v.PatchedVersions)
		name := packageName(v.Package.Ecosystem, v.Package.Name)
		add := func(r finding.Range) {
			if !containsRange(f.Affected, r) {
				f.Affected = append(f.Affected, r)
			}
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
			if !containsRange(byPkg[name], r) {
				byPkg[name] = append(byPkg[name], r)
			}
		}
		if sources.AllVersions(v.VulnerableVersionRange) {
			for _, r := range sources.RangesFromPatched(patched) {
				add(r)
			}
		}
		parsed, broken := 0, 0
		var bad []finding.Range // parsed, but a bound is no version
		for _, expr := range strings.Split(v.VulnerableVersionRange, "||") {
			if sources.AllVersions(expr) {
				continue
			}
			expr = sources.RangeInWords(expr)
			if strings.TrimSpace(expr) == "" {
				continue
			}
			r, err := match.ParseRangeExpr(expr)
			if err != nil {
				broken++
				continue // left out; matching then reports unknown if nothing else applies
			}
			if !versionBounds(r) {
				broken++
				bad = append(bad, r)
				continue
			}
			parsed++
			// ">= 1.28.0" with the fix only in patched_versions ("1.28.4").
			if r.Fixed == "" && r.LastAffected == "" && len(patched) == 1 {
				if p := strings.TrimPrefix(patched[0], ">="); p != "" {
					if _, err := match.ParseVersion(p); err == nil {
						r.Fixed = p
					}
				}
			}
			r = sources.CapGoMajor(v.Package.Ecosystem, v.Package.Name, r)
			for _, r := range perBranch(r, fixes[name]) {
				add(r)
			}
		}
		// A range nobody can parse ("< v3.4.26 and < v3.5.9") next to fixes
		// that parse ("v3.4.26 and v3.5.9"): the fixes say enough. Without
		// usable fixes the broken range stays, and matching reports unknown.
		fallback := []finding.Range(nil)
		if parsed == 0 && broken > 0 {
			fallback = sources.RangesFromPatched(patched)
		}
		if len(fallback) > 0 {
			bad = fallback
		}
		for _, r := range bad {
			add(r)
		}
		f.Fixed = append(f.Fixed, sources.CleanFixed(patched)...)
	}
	// Packages with different version data (a server and its UI): matching
	// the product against all of them would be a guess.
	if len(names) > 1 && slices.ContainsFunc(names[1:], func(n string) bool { return !sameRanges(byPkg[n], byPkg[names[0]]) }) {
		f.Affected = nil
		f.MatchNote = fmt.Sprintf("advisory covers several packages (%s); can't tell which one we run", strings.Join(names, ", "))
	}
	if a.PublishedAt != nil {
		f.Published = *a.PublishedAt
	}
	if a.UpdatedAt != nil {
		f.Modified = *a.UpdatedAt
	}
	f.Canonicalize()
	return f
}

// perBranch splits a coarse range (">= 1.18.0, < 1.40.0") when patched
// versions lie within it, up to its bound ("1.36.10, 1.37.6, 1.38.4,
// 1.39.2"): each fixes its release line, the rest of the range stays
// affected. Any other range is returned as is.
func perBranch(r finding.Range, patched []string) []finding.Range {
	keep := []finding.Range{r}
	hi, err := match.ParseVersion(cmp.Or(r.Fixed, r.LastAffected))
	if err != nil {
		return keep
	}
	var lo *version.Version
	if r.Introduced != "" {
		if lo, err = match.ParseVersion(r.Introduced); err != nil {
			return keep
		}
	}
	type pv struct {
		s string
		v *version.Version
	}
	var in []pv
	for _, p := range patched {
		if v, err := match.ParseVersion(p); err == nil && !v.GreaterThan(hi) && (lo == nil || v.GreaterThan(lo)) {
			in = append(in, pv{p, v})
		}
	}
	if len(in) == 0 {
		return keep
	}
	slices.SortFunc(in, func(a, b pv) int { return a.v.Compare(b.v) })
	var out []finding.Range
	cur, start := finding.Range{Introduced: r.Introduced, IntroducedExclusive: r.IntroducedExclusive}, lo
	for _, p := range in {
		if start == nil || p.v.GreaterThan(start) {
			cur.Fixed = p.s
			out = append(out, cur)
		}
		seg := p.v.Segments()
		next := fmt.Sprintf("%d.%d.0", seg[0], seg[1]+1)
		cur, start = finding.Range{Introduced: next}, version.Must(version.NewVersion(next))
	}
	if hi.GreaterThan(start) || (r.LastAffected != "" && hi.Equal(start)) {
		cur.Fixed, cur.LastAffected = r.Fixed, r.LastAffected
		out = append(out, cur)
	}
	return out
}

// versionBounds reports whether every bound of r is a version: a range
// written in words ("< v3.4.26 and < v3.5.9") parses into a start "and".
func versionBounds(r finding.Range) bool {
	for _, b := range []string{r.Introduced, r.Fixed, r.LastAffected} {
		if b == "" {
			continue
		}
		if _, err := match.ParseVersion(b); err != nil {
			return false
		}
	}
	return true
}

var goMajor = regexp.MustCompile(`/v\d+$`)

// packageName names an advisory's package; the major version paths of a Go
// module (".../v2", ".../v3") are one package.
func packageName(ecosystem, name string) string {
	if strings.EqualFold(ecosystem, "go") {
		return goMajor.ReplaceAllString(name, "")
	}
	return name
}

// sameRanges reports whether a and b hold the same ranges, in any order.
func sameRanges(a, b []finding.Range) bool {
	return len(a) == len(b) && !slices.ContainsFunc(a, func(r finding.Range) bool { return !containsRange(b, r) })
}

func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(id)), "CVE-") }

func containsRange(rs []finding.Range, r finding.Range) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}
