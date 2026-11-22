// Package osv queries OSV.dev by ecosystem and package.
//
// API: POST {base_url}/query with {"package": {...}}; returns full records,
// paginated via next_page_token. OSV has no date filter, so records are
// filtered by their modified timestamp.
package osv

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const Name = "osv"

type Source struct {
	cfg    config.OSVSource
	client *httpx.Client
}

func New(cfg config.OSVSource, client *httpx.Client) *Source {
	return &Source{cfg: cfg, client: client}
}

func (s *Source) Name() string { return Name }

type pkgRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type query struct {
	Package   pkgRef `json:"package"`
	PageToken string `json:"page_token,omitempty"`
}

type queryResponse struct {
	Vulns         []vuln `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}

type vuln struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Related   []string   `json:"related"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Modified  time.Time  `json:"modified"`
	Published time.Time  `json:"published"`
	Withdrawn *time.Time `json:"withdrawn"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package pkgRef `json:"package"`
		Ranges  []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	var out []finding.Finding
	endpoint := strings.TrimRight(s.cfg.BaseURL, "/") + "/query"
	for _, p := range sel.Entry.OSV {
		q := query{Package: pkgRef{Ecosystem: p.Ecosystem, Name: p.Package}}
		for {
			var resp queryResponse
			if err := s.client.PostJSON(ctx, endpoint, q, &resp); err != nil {
				return out, fmt.Errorf("%s/%s: %w", p.Ecosystem, p.Package, err)
			}
			for _, v := range resp.Vulns {
				if v.Withdrawn != nil || v.Modified.Before(since) {
					continue
				}
				out = append(out, toFinding(sel.Product, p, v))
			}
			if resp.NextPageToken == "" {
				break
			}
			q.PageToken = resp.NextPageToken
		}
	}
	return out, nil
}

func toFinding(product string, p config.OSVPackage, v vuln) finding.Finding {
	f := finding.Finding{
		ID:          v.ID,
		Aliases:     slices.Clone(v.Aliases),
		Related:     slices.Clone(v.Related),
		Product:     product,
		Title:       v.Summary,
		Description: sources.Truncate(v.Details, 4000),
		Published:   v.Published,
		Modified:    v.Modified,
		Sources:     []string{Name},
		Severity:    finding.NormalizeSeverity(v.DatabaseSpecific.Severity),
	}
	if f.Title == "" {
		f.Title = sources.Truncate(sources.Headline(v.Details), 160)
	}
	for _, sev := range v.Severity {
		switch sev.Type {
		case "CVSS_V3":
			if score, err := finding.CVSS3Score(sev.Score); err == nil {
				f.CVSS, f.CVSSVector = score, sev.Score
			}
		case "CVSS_V4":
			if f.CVSSVector == "" {
				f.CVSSVector = sev.Score // no numeric score in OSV; severity comes from database_specific
			}
		}
	}
	for _, a := range v.Affected {
		// One record often covers several modules (argo-cd, /v2, /v3);
		// only the queried package's ranges apply.
		if !strings.EqualFold(a.Package.Ecosystem, p.Ecosystem) || a.Package.Name != p.Package {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue // GIT ranges are commit hashes
			}
			for _, rng := range EventsToRanges(r.Events) {
				if sources.IsGoPseudoVersion(rng.Introduced) || sources.IsGoPseudoVersion(rng.Fixed) || sources.IsGoPseudoVersion(rng.LastAffected) {
					continue // untagged module: bounds are commits, not releases
				}
				rng = sources.CapGoMajor(p.Ecosystem, p.Package, rng)
				if !slices.Contains(f.Affected, rng) {
					f.Affected = append(f.Affected, rng)
				}
				if rng.Fixed != "" && !slices.Contains(f.Fixed, rng.Fixed) && isRealFix(p, rng.Fixed) {
					f.Fixed = append(f.Fixed, rng.Fixed)
				}
			}
		}
		for _, v := range a.Versions {
			if !sources.IsGoPseudoVersion(v) {
				f.AffectedVersions = append(f.AffectedVersions, v)
			}
		}
	}
	for _, r := range v.References {
		f.References = append(f.References, r.URL)
	}
	f.Canonicalize()
	return f
}

// isRealFix filters out the synthetic major-version cap added by CapGoMajor.
func isRealFix(p config.OSVPackage, fixed string) bool {
	return sources.GoMajorCap(p.Ecosystem, p.Package) != fixed
}

// EventsToRanges turns an OSV event list into closed/open ranges.
func EventsToRanges(events []map[string]string) []finding.Range {
	var (
		out  []finding.Range
		cur  finding.Range
		open bool
	)
	for _, e := range events {
		switch {
		case e["introduced"] != "":
			if open {
				out = append(out, cur)
			}
			cur, open = finding.Range{Introduced: e["introduced"]}, true
			if cur.Introduced == "0" {
				cur.Introduced = ""
			}
		case e["fixed"] != "":
			cur.Fixed = e["fixed"]
			out, cur, open = append(out, cur), finding.Range{}, false
		case e["last_affected"] != "":
			cur.LastAffected = e["last_affected"]
			out, cur, open = append(out, cur), finding.Range{}, false
		}
	}
	if open {
		out = append(out, cur)
	}
	return out
}
