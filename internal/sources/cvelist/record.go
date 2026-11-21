package cvelist

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/state"
)

// record is the part of a CVE record (CVE JSON 5.x) vulnwatch reads.
type record struct {
	Metadata struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA container   `json:"cna"`
		ADP []container `json:"adp"`
	} `json:"containers"`
}

type container struct {
	Provider struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Title        string `json:"title"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Affected   []affected `json:"affected"`
	Metrics    []metric   `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type affected struct {
	Vendor        string            `json:"vendor"`
	Product       string            `json:"product"`
	PackageName   string            `json:"packageName"`
	CollectionURL string            `json:"collectionURL"`
	CPEs          []string          `json:"cpes"`
	DefaultStatus string            `json:"defaultStatus"`
	Versions      []affectedVersion `json:"versions"`
}

type affectedVersion struct {
	Version         string `json:"version"`
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	VersionType     string `json:"versionType"`
	Status          string `json:"status"`
}

type metric struct {
	V40   *cvss `json:"cvssV4_0"`
	V31   *cvss `json:"cvssV3_1"`
	V30   *cvss `json:"cvssV3_0"`
	V20   *cvss `json:"cvssV2_0"`
	Other *struct {
		Type    string          `json:"type"`
		Content json.RawMessage `json:"content"`
	} `json:"other"`
}

type cvss struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

// cisaADP is the short name of CISA's Vulnrichment container.
const cisaADP = "CISA-ADP"

var (
	idRe     = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	recordRe = regexp.MustCompile(`(?:^|/)CVE-\d{4}-\d{4,}\.json$`)
)

// decode parses a record and checks its ID (it names files and URLs).
func decode(b []byte) (*record, error) {
	var r record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if !idRe.MatchString(r.Metadata.ID) {
		return nil, fmt.Errorf("not a CVE ID: %q", r.Metadata.ID)
	}
	return &r, nil
}

func (r *record) rejected() bool { return strings.EqualFold(r.Metadata.State, "REJECTED") }

// affected lists the affected entries of the CNA and of every ADP.
func (r *record) affected() []affected {
	out := slices.Clone(r.Containers.CNA.Affected)
	for _, a := range r.Containers.ADP {
		out = append(out, a.Affected...)
	}
	return out
}

func (r *record) adp(shortName string) *container {
	for i := range r.Containers.ADP {
		if r.Containers.ADP[i].Provider.ShortName == shortName {
			return &r.Containers.ADP[i]
		}
	}
	return nil
}

// entry is the record's row in the index.
func (r *record) entry() state.CVEListEntry {
	e := state.CVEListEntry{ID: r.Metadata.ID, Updated: r.updated(), Removed: r.rejected()}
	if e.Removed {
		return e
	}
	keys := map[string]bool{}
	for _, a := range r.affected() {
		if k := nameKey(a.Vendor, a.Product); k != "" {
			keys[k] = true
		}
		for _, c := range a.CPEs {
			if k := cpeKey(c); k != "" {
				keys[k] = true
			}
		}
		for _, p := range []string{a.PackageName, a.CollectionURL} {
			if k := pkgKey(p); k != "" {
				keys[k] = true
			}
		}
	}
	e.Keys = slices.Sorted(maps.Keys(keys))
	return e
}

func (r *record) updated() time.Time {
	if t := parseTime(r.Metadata.Updated); !t.IsZero() {
		return t
	}
	return parseTime(r.Metadata.Published)
}

// parseTime reads the record's timestamps; old records lack the zone (UTC).
func parseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// path is where the record lives in the repository: 2026/119xxx/CVE-2026-119618.json.
func path(id string) string {
	parts := strings.Split(id, "-")
	n, _ := strconv.Atoi(parts[2]) // checked by idRe
	return fmt.Sprintf("%s/%dxxx/%s.json", parts[1], n/1000, id)
}

// Match keys, as stored in the index.

// nameKey is a CNA vendor and product pair. Many CNAs write the vendor as
// "n/a" ("n/a" / "keycloak"); such pairs only match catalog products that
// list them, so only a missing product makes a pair useless.
func nameKey(vendor, product string) string {
	v, p := strings.ToLower(strings.TrimSpace(vendor)), strings.ToLower(strings.TrimSpace(product))
	if v == "" || p == "" || p == "n/a" {
		return ""
	}
	return "name:" + v + "\t" + p
}

// cpeKey is vendor and product of a CPE 2.3 string or a CPE 2.2 URI
// ("cpe:/a:redhat:enterprise_linux:10", as Red Hat writes them).
func cpeKey(cpe string) string {
	parts := strings.Split(cpe23(cpe), ":")
	if len(parts) < 5 || parts[0] != "cpe" || parts[1] != "2.3" {
		return ""
	}
	v, p := strings.ToLower(parts[3]), strings.ToLower(parts[4])
	for _, s := range []string{v, p} {
		if s == "" || s == "*" || s == "-" {
			return ""
		}
	}
	return "cpe:" + v + ":" + p
}

// cpe23 writes a CPE 2.2 URI in the CPE 2.3 form.
func cpe23(cpe string) string {
	cpe = strings.TrimSpace(cpe)
	if rest, ok := strings.CutPrefix(cpe, "cpe:/"); ok {
		return "cpe:2.3:" + rest
	}
	return cpe
}

// pkgKey is a package name or repository URL without scheme, trailing
// slash or ".git", so "https://github.com/foo/bar" matches the Go module
// github.com/foo/bar.
func pkgKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range []string{"https://", "http://"} {
		n = strings.TrimPrefix(n, p)
	}
	n = strings.TrimSuffix(strings.TrimSuffix(n, "/"), ".git")
	if n == "" || n == "n/a" {
		return ""
	}
	return "pkg:" + n
}

// matcher matches records to one catalog product: by its cvelist: names,
// its nvd: CPEs and its osv: package names.
type matcher struct {
	keys  []string // index keys
	names map[string]bool
	cpes  []string
	pkgs  map[string]bool
}

func newMatcher(e config.CatalogEntry) matcher {
	m := matcher{names: map[string]bool{}, pkgs: map[string]bool{}}
	keys := map[string]bool{}
	for _, n := range e.CVEList {
		if k := nameKey(n.Vendor, n.Product); k != "" {
			m.names[k], keys[k] = true, true
		}
	}
	for _, c := range e.NVD {
		// A CPE with a wildcard vendor or product can't be looked up.
		if k := cpeKey(c); k != "" {
			m.cpes = append(m.cpes, c)
			keys[k] = true
		}
	}
	for _, p := range e.OSV {
		if k := pkgKey(p.Package); k != "" {
			m.pkgs[k], keys[k] = true, true
		}
	}
	m.keys = slices.Sorted(maps.Keys(keys))
	return m
}

func (m matcher) empty() bool { return len(m.keys) == 0 }

// hasKey reports whether an index entry carries one of the product's keys.
func (m matcher) hasKey(keys []string) bool {
	return slices.ContainsFunc(keys, func(k string) bool { return slices.Contains(m.keys, k) })
}

// matches reports whether an affected entry is the product's.
func (m matcher) matches(a affected) bool {
	if m.names[nameKey(a.Vendor, a.Product)] {
		return true
	}
	if m.pkgs[pkgKey(a.PackageName)] || m.pkgs[pkgKey(a.CollectionURL)] {
		return true
	}
	for _, c := range a.CPEs {
		if slices.ContainsFunc(m.cpes, func(sel string) bool { return sources.CPEMatches(sel, cpe23(c)) }) {
			return true
		}
	}
	return false
}

const maxDescription = 4000 // runes, as the NVD source keeps

// toFinding converts a record for one product from the affected entries
// that are the product's (not the whole record). ok is false for rejected
// records, records that don't name the product, and records whose entries
// for it all say "unaffected".
func toFinding(product string, r *record, m matcher) (f finding.Finding, ok bool) {
	if r.rejected() {
		return f, false
	}
	var ours []affected
	for _, a := range r.affected() {
		if m.matches(a) {
			ours = append(ours, a)
		}
	}
	if !slices.ContainsFunc(ours, affects) {
		return f, false
	}
	cna := r.Containers.CNA
	f = finding.Finding{
		ID:        r.Metadata.ID,
		Product:   product,
		Published: parseTime(r.Metadata.Published),
		Modified:  r.updated(),
		Sources:   []string{Name},
	}
	for _, d := range cna.Descriptions {
		if strings.HasPrefix(strings.ToLower(d.Lang), "en") {
			f.Description = sources.Truncate(strings.TrimSpace(d.Value), maxDescription)
			break
		}
	}
	f.Title = sources.Truncate(strings.TrimSpace(cna.Title), 160)
	if f.Title == "" {
		f.Title = sources.Truncate(sources.Headline(f.Description), 160)
	}
	for _, ref := range cna.References {
		f.References = append(f.References, ref.URL)
	}
	f.Affected, f.AffectedVersions = versions(ours)
	for _, rg := range f.Affected {
		if rg.Fixed != "" {
			f.Fixed = append(f.Fixed, rg.Fixed)
		}
	}
	cisa := r.adp(cisaADP)
	c, scored := pickCVSS(cna.Metrics)
	if !scored && cisa != nil {
		c, scored = pickCVSS(cisa.Metrics)
	}
	if scored {
		f.CVSS, f.CVSSVector, f.Severity = c.BaseScore, c.VectorString, finding.NormalizeSeverity(c.BaseSeverity)
	} else {
		f.Severity = textSeverity(cna.Metrics)
	}
	if cisa != nil {
		f.SSVCExploitation, f.SSVCAutomatable, f.SSVCTechnicalImpact = ssvc(cisa.Metrics)
	}
	f.Canonicalize()
	return f, true
}

// affects reports whether an entry may say the product is affected: not
// when everything it lists, and its default, is "unaffected".
func affects(a affected) bool {
	if !strings.EqualFold(a.DefaultStatus, "unaffected") {
		return true
	}
	return slices.ContainsFunc(a.Versions, func(v affectedVersion) bool { return strings.EqualFold(v.Status, "affected") })
}

// versions returns the affected ranges and versions of the product's
// entries. Every affected entry must be usable, otherwise there is no
// version data (match unknown) rather than a partial answer: git commits,
// versions the version parser rejects, and entries affected by default
// (defaultStatus "affected": the versions not listed are affected too).
func versions(entries []affected) ([]finding.Range, []string) {
	var (
		ranges []finding.Range
		exact  []string
	)
	for _, a := range entries {
		if strings.EqualFold(a.DefaultStatus, "affected") {
			return nil, nil
		}
		for _, v := range a.Versions {
			if !strings.EqualFold(v.Status, "affected") {
				continue
			}
			r, x, ok := sources.CNAVersion(v.Version, v.LessThan, v.LessThanOrEqual, v.VersionType)
			switch {
			case !ok || !parses(r.Introduced, r.Fixed, r.LastAffected, x):
				return nil, nil
			case x != "":
				if !slices.Contains(exact, x) {
					exact = append(exact, x)
				}
			case !slices.Contains(ranges, r):
				ranges = append(ranges, r)
			}
		}
	}
	return ranges, exact
}

// parses reports whether every non-empty version parses.
func parses(vs ...string) bool {
	for _, v := range vs {
		if v == "" {
			continue
		}
		if _, err := match.ParseVersion(v); err != nil {
			return false
		}
	}
	return true
}

// pickCVSS returns the newest CVSS version among the metrics.
func pickCVSS(ms []metric) (cvss, bool) {
	for _, get := range []func(metric) *cvss{
		func(m metric) *cvss { return m.V40 },
		func(m metric) *cvss { return m.V31 },
		func(m metric) *cvss { return m.V30 },
		func(m metric) *cvss { return m.V20 },
	} {
		for _, m := range ms {
			if c := get(m); c != nil && c.BaseScore > 0 {
				return *c, true
			}
		}
	}
	return cvss{}, false
}

// textSeverity is the CNA's severity in words, for records without CVSS
// (Apache: "Textual description of severity" = "critical").
func textSeverity(ms []metric) string {
	for _, m := range ms {
		if m.Other == nil || !strings.Contains(strings.ToLower(m.Other.Type), "severity") {
			continue
		}
		var c struct {
			Text  string `json:"text"`
			Value string `json:"value"`
		}
		if json.Unmarshal(m.Other.Content, &c) != nil {
			continue
		}
		if s := finding.NormalizeSeverity(c.Text + c.Value); s != finding.SeverityUnknown {
			return s
		}
	}
	return ""
}

// ssvc reads CISA's SSVC decision points: an "ssvc" metric whose options
// are single-key maps ({"Exploitation": "poc"}).
func ssvc(ms []metric) (exploitation, automatable, impact string) {
	for _, m := range ms {
		if m.Other == nil || !strings.EqualFold(m.Other.Type, "ssvc") {
			continue
		}
		var c struct {
			Options []map[string]string `json:"options"`
		}
		if json.Unmarshal(m.Other.Content, &c) != nil {
			continue
		}
		for _, o := range c.Options {
			for k, v := range o {
				v = strings.ToLower(strings.TrimSpace(v))
				switch strings.ToLower(k) {
				case "exploitation":
					exploitation = v
				case "automatable":
					automatable = v
				case "technical impact":
					impact = v
				}
			}
		}
	}
	return exploitation, automatable, impact
}
