// Package sources defines the interfaces implemented by every advisory
// source and enricher, plus small helpers shared between them.
package sources

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/hashicorp/go-version"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/textx"
)

// Selector is one product's catalog entry, handed to every source.
type Selector struct {
	Product string
	Entry   config.CatalogEntry
	// OS and Versions are set for the nodes' kernel (catalog.KernelProduct()):
	// the distribution release and the running kernel version(s).
	OS       *config.StackOS
	Versions []string
}

// Source fetches findings for one product, published or modified since a time.
// A source with nothing configured for the product returns (nil, nil).
type Source interface {
	Name() string
	Fetch(ctx context.Context, sel Selector, since time.Time) ([]finding.Finding, error)
}

// InCluster reports whether a source reads the cluster vulnwatch runs in
// (Trivy): its findings belong to the local stack only, never a tenant's.
func InCluster(s Source) bool {
	c, ok := s.(interface{ InCluster() bool })
	return ok && c.InCluster()
}

// Enricher adds data (KEV, EPSS, public exploits) to already collected findings in place.
type Enricher interface {
	Name() string
	Enrich(ctx context.Context, fs []finding.Finding) error
}

// Cache is an optional byte cache with fetch timestamps (backed by the state DB).
type Cache interface {
	GetCache(ctx context.Context, key string) (body []byte, fetched time.Time, ok bool, err error)
	PutCache(ctx context.Context, key string, body []byte) error
}

var goMajorSuffix = regexp.MustCompile(`/v(\d+)$`)

// CapGoMajor bounds an open-ended range for a Go module with a /vN major
// suffix at <N+1.0.0. Advisories list one entry per major module path
// (".../v2: >= 2.1.0" with no fix), and without the cap that range would
// also match every 3.x version of the product. A range without a start
// ("introduced: 0", no fix: every version) stays as it is: the Go
// vulnerability database writes that for modules it couldn't map to a fixed
// release (GO-2024-2529 for go.etcd.io/etcd/v3), so it is no version data,
// not "every N.x is affected".
func CapGoMajor(ecosystem, pkg string, r finding.Range) finding.Range {
	if r.Fixed != "" || r.LastAffected != "" || r.Introduced == "" {
		return r
	}
	if limit := GoMajorCap(ecosystem, pkg); limit != "" {
		r.Fixed = limit
	}
	return r
}

// GoMajorCap is the synthetic upper bound CapGoMajor sets for a Go module
// with a /vN (N >= 2) suffix: "N+1.0.0"; empty for anything else.
func GoMajorCap(ecosystem, pkg string) string {
	if !strings.EqualFold(ecosystem, "go") {
		return ""
	}
	m := goMajorSuffix.FindStringSubmatch(pkg)
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 2 {
		return ""
	}
	return strconv.Itoa(n+1) + ".0.0"
}

var pseudoVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+-(?:[0-9A-Za-z.-]*\.)?\d{14}-[0-9a-f]{12}(?:\+incompatible)?$`)

// IsGoPseudoVersion reports whether v is a Go pseudo-version
// ("0.0.0-20260714163218-90272575e5f5"). Modules without semver tags get
// these in OSV; they say nothing about the product's release versions.
func IsGoPseudoVersion(v string) bool { return pseudoVersion.MatchString(v) }

var tagRe = regexp.MustCompile(`<[^>]*>`)

// StripHTML removes tags and collapses whitespace; good enough for feed summaries.
func StripHTML(s string) string {
	s = tagRe.ReplaceAllString(s, " ")
	for _, r := range []struct{ from, to string }{{"&amp;", "&"}, {"&lt;", "<"}, {"&gt;", ">"}, {"&quot;", `"`}, {"&#39;", "'"}, {"&nbsp;", " "}} {
		s = strings.ReplaceAll(s, r.from, r.to)
	}
	return strings.Join(strings.Fields(s), " ")
}

// Truncate shortens s to at most n runes at a word boundary, ellipsis
// included (textx.Truncate).
func Truncate(s string, n int) string { return textx.Truncate(s, n) }

var opSpace = regexp.MustCompile(`([<>=]=?)\s+`)

// SplitVersions splits a list of versions separated by commas or
// whitespace ("1.36.12 1.37.8", "1.5.13, 1.6.7"), as repository advisories
// write patched_versions. An operator stays with its version (">= 1.2.3").
func SplitVersions(s string) []string {
	return strings.FieldsFunc(opSpace.ReplaceAllString(s, "$1"), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// CleanFixed keeps the fixed versions people can upgrade to: no "N/A" or
// other non-versions, no Go pseudo-versions, no "+incompatible" twins, no
// second spelling of the same version ("v2.13.9", "2.13.9") and no
// pre-release whose final release is listed too.
func CleanFixed(vs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vs {
		v = strings.TrimSuffix(strings.TrimSpace(v), "+incompatible")
		if v == "" || IsGoPseudoVersion(v) {
			continue
		}
		pv, err := match.ParseVersion(v)
		if err != nil || seen[pv.String()] {
			continue
		}
		seen[pv.String()] = true
		out = append(out, v)
	}
	return slices.DeleteFunc(out, func(v string) bool {
		pv, _ := match.ParseVersion(v)
		if pv.Prerelease() == "" {
			return false
		}
		core := pv.Core().String()
		return slices.ContainsFunc(out, func(o string) bool {
			po, _ := match.ParseVersion(o)
			return po.Prerelease() == "" && po.Core().String() == core
		})
	})
}

var andNewer = regexp.MustCompile(`(?i)^\s*(\S+)\s+and\s+(?:newer|later|above)\s*$`)

// RangeInWords turns "RELEASE.2024-06-06T09-36-42Z and newer" (as some
// repository advisories write it) into ">= RELEASE.2024-06-06T09-36-42Z".
func RangeInWords(expr string) string {
	return andNewer.ReplaceAllString(expr, ">= $1")
}

// AllVersions reports whether a range expression means every version
// ("All", "*"), as some repository advisories write it.
func AllVersions(expr string) bool {
	switch strings.ToLower(strings.TrimSpace(expr)) {
	case "all", "*", "all versions":
		return true
	}
	return false
}

// RangesFromPatched builds affected ranges from patched versions alone
// ("1.5.13, 1.6.7, 1.7.1"): everything below the lowest, and each later
// release line from its .0 up to its patch.
func RangesFromPatched(patched []string) []finding.Range {
	type pv struct {
		s string
		v *version.Version
	}
	var ps []pv
	for _, p := range patched {
		p = strings.TrimSpace(p)
		if v, err := match.ParseVersion(p); err == nil {
			ps = append(ps, pv{p, v})
		}
	}
	slices.SortFunc(ps, func(a, b pv) int { return a.v.Compare(b.v) })
	var out []finding.Range
	for i, p := range ps {
		if i == 0 {
			out = append(out, finding.Range{Fixed: p.s})
			continue
		}
		seg := p.v.Segments()
		if len(seg) < 2 {
			continue
		}
		out = append(out, finding.Range{Introduced: fmt.Sprintf("%d.%d.0", seg[0], seg[1]), Fixed: p.s})
	}
	return out
}
