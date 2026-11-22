// Package finding holds the normalized vulnerability model shared by all
// sources, plus cross-source deduplication and change detection.
package finding

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/imageref"
)

// Severity levels, lowest to highest.
const (
	SeverityUnknown  = "unknown"
	SeverityNone     = "none"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var severityRank = map[string]int{
	SeverityUnknown: 0, SeverityNone: 1, SeverityLow: 2, SeverityMedium: 3, SeverityHigh: 4, SeverityCritical: 5,
}

// SeverityRank orders severities; unknown values rank lowest.
func SeverityRank(s string) int { return severityRank[strings.ToLower(s)] }

// NormalizeSeverity maps vendor spellings ("MODERATE", "Important") to our levels.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high", "important":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none":
		return SeverityNone
	}
	return SeverityUnknown
}

// SeverityFromCVSS maps a CVSS v3/v4 base score to a severity.
func SeverityFromCVSS(score float64) string {
	switch {
	case score <= 0:
		return SeverityUnknown
	case score >= 9:
		return SeverityCritical
	case score >= 7:
		return SeverityHigh
	case score >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// Finding is one vulnerability for one product, normalized across sources.
type Finding struct {
	ID               string    `json:"id"`
	Aliases          []string  `json:"aliases,omitempty"`
	Related          []string  `json:"related,omitempty"` // mentioned IDs that are not the same vulnerability
	Product          string    `json:"product"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	CVSS             float64   `json:"cvss,omitempty"`
	CVSSVector       string    `json:"cvss_vector,omitempty"`
	Severity         string    `json:"severity"`
	Affected         []Range   `json:"affected,omitempty"`
	AffectedVersions []string  `json:"affected_versions,omitempty"`
	Fixed            []string  `json:"fixed,omitempty"`
	Published        time.Time `json:"published,omitzero"`
	Modified         time.Time `json:"modified,omitzero"`
	References       []string  `json:"references,omitempty"`
	Sources          []string  `json:"sources"`

	// Enrichment.
	KEV            bool    `json:"kev,omitempty"`
	KEVDateAdded   string  `json:"kev_date_added,omitempty"`
	EPSS           float64 `json:"epss,omitempty"`
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	// Red Hat's rating (critical, important, moderate, low), statement and
	// mitigation; about Red Hat's builds, but they name the conditions under
	// which a flaw is exploitable.
	RedHatSeverity   string `json:"redhat_severity,omitempty"`
	RedHatStatement  string `json:"redhat_statement,omitempty"`
	RedHatMitigation string `json:"redhat_mitigation,omitempty"`
	// CISA's SSVC decision points from the CVE record (Vulnrichment), lower
	// case: exploitation none, poc or active; automatable yes or no;
	// technical impact partial or total.
	SSVCExploitation    string `json:"ssvc_exploitation,omitempty"`
	SSVCAutomatable     string `json:"ssvc_automatable,omitempty"`
	SSVCTechnicalImpact string `json:"ssvc_technical_impact,omitempty"`

	// Deterministic version match (see package match).
	Match       string `json:"match,omitempty"`
	MatchDetail string `json:"match_detail,omitempty"`
	// MatchNote is a source's reason for giving no version data (GHSA: an
	// advisory covering several packages); the match detail when no source
	// has any.
	MatchNote string `json:"match_note,omitempty"`

	// Packages are vulnerable packages Trivy found in our running images.
	Packages []Package `json:"packages,omitempty"`
}

// SourceTrivy is the source name of image findings.
const SourceTrivy = "trivy"

// Package is a vulnerable package in a running image.
type Package struct {
	Image     string `json:"image"`          // repository:tag
	Name      string `json:"name"`           // e.g. libssl3, golang.org/x/net
	Type      string `json:"type,omitempty"` // package URL type: deb, rpm, apk, golang, maven, npm, pypi
	Installed string `json:"installed"`
	Fixed     string `json:"fixed,omitempty"`
}

func (p Package) String() string {
	s := p.Name + " " + p.Installed
	if p.Fixed != "" {
		s += " (fixed in " + p.Fixed + ")"
	}
	return s + " in " + p.Image
}

// ImageName is the image's last path segment and tag ("argocd:v3.5.6"),
// without registry, repository path or digest.
func (p Package) ImageName() string {
	if strings.TrimSpace(p.Image) == "" {
		return ""
	}
	r := imageref.Parse(p.Image)
	name := path.Base(r.Path)
	if r.Tag != "" {
		name += ":" + r.Tag
	}
	return name
}

// Brief is String with the image as ImageName: what the triage prompt says
// about the package (no registry or internal image path leaves vulnwatch).
func (p Package) Brief() string {
	return strings.TrimSuffix(p.String(), p.Image) + p.ImageName()
}

// InImage reports whether Trivy found the vulnerable package running.
func (f *Finding) InImage() bool { return len(f.Packages) > 0 }

// ImageOnly reports whether only Trivy reports the finding: no advisory
// for the product says it is affected, only a package inside its image.
func (f *Finding) ImageOnly() bool {
	return f.InImage() && !slices.ContainsFunc(f.Sources, func(s string) bool { return s != SourceTrivy })
}

// Confirmed reports whether an advisory for the product reports it and
// Trivy found the vulnerable package in the running image.
func (f *Finding) Confirmed() bool { return f.InImage() && !f.ImageOnly() }

var cveRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// ExtractCVEs returns the unique CVE IDs mentioned in text, upper-cased, in order.
func ExtractCVEs(text string) []string {
	var out []string
	for _, m := range cveRe.FindAllString(text, -1) {
		m = strings.ToUpper(m)
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// HasVersionData reports whether the finding says which versions are
// affected. An "all versions" range (no bounds at all) doesn't: sources use
// it for "not specified" (e.g. NVD mapping a 2016 OpenShift CVE to every
// Kubernetes version), so it is treated like no data.
func (f *Finding) HasVersionData() bool {
	if len(f.AffectedVersions) > 0 {
		return true
	}
	return slices.ContainsFunc(f.Affected, func(r Range) bool { return !r.AllVersions() })
}

// TagSource records which source reported the version data of a finding
// fresh from one source, so the match can still tell the sources apart once
// Dedup merged them: every range gets the source, and every listed affected
// version becomes an Exact range. Findings with more or fewer than one
// source are left as they are.
func (f *Finding) TagSource() {
	if len(f.Sources) != 1 || len(f.Affected)+len(f.AffectedVersions) == 0 {
		return
	}
	src := f.Sources[0]
	tagged := make([]Range, 0, len(f.Affected)+len(f.AffectedVersions))
	for _, r := range f.Affected {
		r.Source = src
		tagged = append(tagged, r)
	}
	for _, v := range f.AffectedVersions {
		r := Range{Introduced: v, LastAffected: v, Exact: true, Source: src}
		if !slices.Contains(tagged, r) {
			tagged = append(tagged, r)
		}
	}
	f.Affected, f.AffectedVersions = tagged, nil
}

// IDs returns the canonical ID plus aliases.
func (f *Finding) IDs() []string {
	return uniq(append([]string{f.ID}, f.Aliases...))
}

// CVEs returns all CVE IDs among the finding's IDs.
func (f *Finding) CVEs() []string {
	var out []string
	for _, id := range f.IDs() {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

// RedHatRank orders Red Hat's ratings: low 1 … critical 4, else 0.
func RedHatRank(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "moderate":
		return 2
	case "important":
		return 3
	case "critical":
		return 4
	}
	return 0
}

// SSVCExploitationRank orders SSVC exploitation states: none 1, poc 2,
// active 3, else 0.
func SSVCExploitationRank(s string) int {
	switch strings.ToLower(s) {
	case "none":
		return 1
	case "poc":
		return 2
	case "active":
		return 3
	}
	return 0
}

// Canonicalize picks the canonical ID (CVE > GHSA > other, then lexical),
// moves the rest into Aliases and fills derived fields.
func (f *Finding) Canonicalize() {
	ids := uniq(append([]string{f.ID}, f.Aliases...))
	slices.SortFunc(ids, func(a, b string) int {
		return cmp.Or(cmp.Compare(idRank(a), idRank(b)), cmp.Compare(a, b))
	})
	if len(ids) > 0 {
		f.ID, f.Aliases = ids[0], ids[1:]
	}
	if len(f.Aliases) == 0 {
		f.Aliases = nil
	}
	f.Related = slices.DeleteFunc(uniq(f.Related), func(r string) bool { return slices.Contains(ids, r) })
	if len(f.Related) == 0 {
		f.Related = nil
	}
	if f.Severity == "" || f.Severity == SeverityUnknown {
		f.Severity = SeverityFromCVSS(f.CVSS)
	}
	f.Sources = uniq(f.Sources)
	slices.Sort(f.Sources)
}

func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	}
	return 2
}

func uniq(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// SourcePriority orders sources for field precedence when merging; lower
// wins. Unknown sources rank last. The CVE record (cvelist: the CNA's CVSS,
// else CISA's) comes before NVD's own analysis.
var SourcePriority = map[string]int{"ghsa": 0, "cvelist": 1, "nvd": 2, "osv": 3, "kubernetes_cve_feed": 4, "rss": 5, SourceTrivy: 6}

func priorityOf(f Finding) int {
	best := len(SourcePriority)
	for _, s := range f.Sources {
		if p, ok := SourcePriority[s]; ok && p < best {
			best = p
		}
	}
	return best
}

// Dedup merges findings that describe the same vulnerability for the same
// product, linked transitively through their IDs and aliases.
// Clone returns a copy that shares no slices with f.
func (f Finding) Clone() Finding {
	f.Aliases = slices.Clone(f.Aliases)
	f.Related = slices.Clone(f.Related)
	f.Affected = slices.Clone(f.Affected)
	f.AffectedVersions = slices.Clone(f.AffectedVersions)
	f.Fixed = slices.Clone(f.Fixed)
	f.References = slices.Clone(f.References)
	f.Sources = slices.Clone(f.Sources)
	f.Packages = slices.Clone(f.Packages)
	return f
}

func Dedup(in []Finding) []Finding {
	// Union-find over finding indices, keyed by product+ID.
	parent := make([]int, len(in))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, f := range in {
		for _, id := range f.IDs() {
			key := f.Product + "\x00" + id
			if j, ok := owner[key]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[key] = i
			}
		}
	}
	groups := map[int][]Finding{}
	var roots []int
	for i, f := range in {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], f)
	}
	out := make([]Finding, 0, len(roots))
	for _, r := range roots {
		out = append(out, merge(groups[r]))
	}
	slices.SortFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Product, b.Product), cmp.Compare(a.ID, b.ID))
	})
	return out
}

func merge(group []Finding) Finding {
	slices.SortStableFunc(group, func(a, b Finding) int { return cmp.Compare(priorityOf(a), priorityOf(b)) })
	m := group[0]
	m.Aliases = slices.Clone(m.Aliases)
	m.Packages = slices.Clone(m.Packages)
	for _, f := range group[1:] {
		m.Aliases = append(m.Aliases, f.IDs()...)
		m.Related = append(m.Related, f.Related...)
		m.Title = cmp.Or(m.Title, f.Title)
		m.Description = cmp.Or(m.Description, f.Description)
		if m.CVSS == 0 && f.CVSS > 0 {
			m.CVSS, m.CVSSVector = f.CVSS, f.CVSSVector
		}
		if SeverityRank(f.Severity) > SeverityRank(m.Severity) && m.CVSS == 0 {
			m.Severity = f.Severity
		}
		for _, r := range f.Affected {
			if !slices.Contains(m.Affected, r) {
				m.Affected = append(m.Affected, r)
			}
		}
		m.AffectedVersions = append(m.AffectedVersions, f.AffectedVersions...)
		m.Fixed = append(m.Fixed, f.Fixed...)
		if !f.Published.IsZero() && (m.Published.IsZero() || f.Published.Before(m.Published)) {
			m.Published = f.Published
		}
		if f.Modified.After(m.Modified) {
			m.Modified = f.Modified
		}
		m.References = append(m.References, f.References...)
		m.Sources = append(m.Sources, f.Sources...)
		m.KEV = m.KEV || f.KEV
		m.KEVDateAdded = cmp.Or(m.KEVDateAdded, f.KEVDateAdded)
		m.EPSS = max(m.EPSS, f.EPSS)
		m.EPSSPercentile = max(m.EPSSPercentile, f.EPSSPercentile)
		if RedHatRank(f.RedHatSeverity) > RedHatRank(m.RedHatSeverity) {
			m.RedHatSeverity = f.RedHatSeverity
		}
		m.RedHatStatement = cmp.Or(m.RedHatStatement, f.RedHatStatement)
		m.RedHatMitigation = cmp.Or(m.RedHatMitigation, f.RedHatMitigation)
		m.MatchNote = cmp.Or(m.MatchNote, f.MatchNote)
		if SSVCExploitationRank(f.SSVCExploitation) > SSVCExploitationRank(m.SSVCExploitation) {
			m.SSVCExploitation = f.SSVCExploitation
		}
		m.SSVCAutomatable = cmp.Or(m.SSVCAutomatable, f.SSVCAutomatable)
		m.SSVCTechnicalImpact = cmp.Or(m.SSVCTechnicalImpact, f.SSVCTechnicalImpact)
		for _, p := range f.Packages {
			if !slices.Contains(m.Packages, p) {
				m.Packages = append(m.Packages, p)
			}
		}
	}
	m.AffectedVersions = uniq(m.AffectedVersions)
	m.Fixed = uniq(m.Fixed)
	m.References = uniq(m.References)
	m.Canonicalize()
	return m
}

// Snapshot holds the fields whose change makes a finding worth re-reporting.
type Snapshot struct {
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
	KEV      bool     `json:"kev"`
	Fixed    []string `json:"fixed"`
	Match    string   `json:"match"`
}

// Snapshot returns the material state of the finding.
func (f *Finding) Snapshot() Snapshot {
	fixed := slices.Clone(f.Fixed)
	slices.Sort(fixed)
	return Snapshot{Severity: f.Severity, CVSS: f.CVSS, KEV: f.KEV, Fixed: fixed, Match: f.Match}
}

// Hash is a stable content hash of the snapshot.
func (s Snapshot) Hash() string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Changes lists material changes from prev to cur, or nil if none.
// Material: severity raised, added to KEV, a new fixed version, or our
// affected status changed.
func Changes(prev, cur Snapshot) []string {
	var out []string
	if SeverityRank(cur.Severity) > SeverityRank(prev.Severity) {
		out = append(out, fmt.Sprintf("severity raised from %s to %s", prev.Severity, cur.Severity))
	}
	if cur.KEV && !prev.KEV {
		out = append(out, "added to CISA KEV")
	}
	var newFixed []string
	for _, v := range cur.Fixed {
		if !slices.Contains(prev.Fixed, v) {
			newFixed = append(newFixed, v)
		}
	}
	if len(newFixed) > 0 {
		out = append(out, "fixed version released: "+strings.Join(newFixed, ", "))
	}
	if cur.Match != prev.Match && prev.Match != "" {
		out = append(out, fmt.Sprintf("affected status changed from %s to %s", prev.Match, cur.Match))
	}
	return out
}
