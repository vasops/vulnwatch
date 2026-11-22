// Package nvd queries the NVD CVE API 2.0 by CPE match string over a
// last-modified window.
//
// API: GET {base_url}?virtualMatchString=...&lastModStartDate=...&lastModEndDate=...
// Windows longer than max_window are split; pages via startIndex. The
// optional key is sent in the apiKey header. Errors arrive as HTTP 404 with a
// "message" header.
package nvd

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const Name = "nvd"

// NVD timestamps carry no zone; they are UTC.
const tsLayout = "2006-01-02T15:04:05.000"

type Source struct {
	cfg     config.NVDSource
	client  *httpx.Client
	apiKey  string
	limiter *httpx.Limiter
	slots   chan struct{} // requests in flight, retries included; nil: no limit
	now     func() time.Time

	start sync.Once
	end   time.Time // budget end, set by the first request; zero: no budget
}

func New(cfg config.NVDSource, client *httpx.Client, getenv func(string) string) *Source {
	s := &Source{cfg: cfg, client: client, apiKey: getenv(cfg.APIKeyEnv), now: time.Now}
	interval := cfg.RequestInterval.D()
	if s.apiKey != "" {
		interval = cfg.RequestIntervalWithKey.D()
	}
	s.limiter = httpx.NewLimiter(interval)
	if cfg.MaxInFlight > 0 {
		s.slots = make(chan struct{}, cfg.MaxInFlight)
	}
	return s
}

// get sends one request, holding an in-flight slot for it and its retries:
// NVD answers slowly (tens of seconds when busy) and turns a client's
// parallel requests away with 503s.
//
// The budget (sources.nvd.budget) starts with the first request: a busy NVD
// must not use up run.deadline. Requests after it, or still open at its
// end, fail; the source keeps its window and the next run asks again.
func (s *Source) get(ctx context.Context, url string, headers map[string]string, v any) error {
	outer := ctx
	b := s.cfg.Budget.D()
	used := func() error { return fmt.Errorf("NVD time budget of %s used up; the next run asks again", b) }
	if b > 0 {
		s.start.Do(func() { s.end = time.Now().Add(b) })
		if !time.Now().Before(s.end) {
			return used()
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, s.end)
		defer cancel()
	}
	err := s.send(ctx, url, headers, v)
	if err != nil && b > 0 && outer.Err() == nil && ctx.Err() != nil {
		return used()
	}
	return err
}

func (s *Source) send(ctx context.Context, url string, headers map[string]string, v any) error {
	if s.slots != nil {
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := s.limiter.Wait(ctx); err != nil {
		return err
	}
	_, err := s.client.GetJSON(ctx, url, headers, v)
	return err
}

func (s *Source) Name() string { return Name }

type nvdTime struct{ time.Time }

func (t *nvdTime) UnmarshalJSON(b []byte) error {
	str := strings.Trim(string(b), `"`)
	if str == "" || str == "null" {
		return nil
	}
	for _, layout := range []string{tsLayout, "2006-01-02T15:04:05", time.RFC3339Nano} {
		if v, err := time.ParseInLocation(layout, str, time.UTC); err == nil {
			t.Time = v
			return nil
		}
	}
	return fmt.Errorf("nvd: bad timestamp %q", str)
}

type cvssMetric struct {
	Type     string `json:"type"`
	CVSSData struct {
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"` // v2 keeps it outside cvssData
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}

type cve struct {
	ID           string  `json:"id"`
	Published    nvdTime `json:"published"`
	LastModified nvdTime `json:"lastModified"`
	VulnStatus   string  `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V40 []cvssMetric `json:"cvssMetricV40"`
		V31 []cvssMetric `json:"cvssMetricV31"`
		V30 []cvssMetric `json:"cvssMetricV30"`
		V2  []cvssMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Configurations []struct {
		Operator string `json:"operator"` // AND: every node must match
		Negate   bool   `json:"negate"`
		Nodes    []node `json:"nodes"`
	} `json:"configurations"`
	Affected []struct {
		AffectedData []struct {
			Vendor   string `json:"vendor"`
			Product  string `json:"product"`
			Versions []struct {
				Version         string `json:"version"`
				LessThan        string `json:"lessThan"`
				LessThanOrEqual string `json:"lessThanOrEqual"`
				VersionType     string `json:"versionType"`
				Status          string `json:"status"`
			} `json:"versions"`
		} `json:"affectedData"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type response struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE cve `json:"cve"`
	} `json:"vulnerabilities"`
}

func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	if len(sel.Entry.NVD) == 0 {
		return nil, nil
	}
	headers := map[string]string{}
	if s.apiKey != "" {
		headers["apiKey"] = s.apiKey
	}
	end := s.now().UTC()
	var out []finding.Finding
	for _, cpe := range sel.Entry.NVD {
		// A zero since means the full history: no date filter, which NVD
		// answers without the 120-day window limit.
		ws := [][2]time.Time{{}}
		if !since.IsZero() {
			ws = windows(since.UTC(), end, s.cfg.MaxWindow.D())
		}
		for _, w := range ws {
			start := 0
			for {
				q := url.Values{}
				q.Set("virtualMatchString", cpe)
				if !w[0].IsZero() {
					q.Set("lastModStartDate", w[0].Format(tsLayout)+"Z")
					q.Set("lastModEndDate", w[1].Format(tsLayout)+"Z")
				}
				q.Set("resultsPerPage", strconv.Itoa(max(s.cfg.ResultsPerPage, 1)))
				q.Set("noRejected", "")
				q.Set("startIndex", strconv.Itoa(start))
				var resp response
				if err := s.get(ctx, s.cfg.BaseURL+"?"+q.Encode(), headers, &resp); err != nil {
					if ctx.Err() != nil {
						return out, err
					}
					return out, fmt.Errorf("%s: %w", cpe, err)
				}
				for _, v := range resp.Vulnerabilities {
					if v.CVE.VulnStatus == "Rejected" {
						continue
					}
					f, ok := toFinding(sel.Product, cpe, v.CVE)
					if !ok {
						continue // our CPE is only a platform here (e.g. "runs on Kubernetes")
					}
					if s.cfg.DetailURL != "" {
						f.References = append([]string{strings.ReplaceAll(s.cfg.DetailURL, "{id}", f.ID)}, f.References...)
					}
					out = append(out, f)
				}
				start += len(resp.Vulnerabilities)
				if len(resp.Vulnerabilities) == 0 || start >= resp.TotalResults {
					break
				}
			}
		}
	}
	return out, nil
}

// windows splits [from, to] into chunks no longer than maxLen.
func windows(from, to time.Time, maxLen time.Duration) [][2]time.Time {
	var out [][2]time.Time
	for from.Before(to) {
		end := from.Add(maxLen)
		if end.After(to) {
			end = to
		}
		out = append(out, [2]time.Time{from, end})
		from = end
	}
	return out
}

// toFinding converts a CVE for the product. ok is false when the product's
// CPE appears in the CVE only as non-vulnerable (a platform the vulnerable
// software runs on), which virtualMatchString also returns.
func toFinding(product, selector string, c cve) (f finding.Finding, ok bool) {
	f = finding.Finding{
		ID:        c.ID,
		Product:   product,
		Published: c.Published.Time,
		Modified:  c.LastModified.Time,
		Sources:   []string{Name},
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			f.Description = sources.Truncate(d.Value, 4000)
			break
		}
	}
	f.Title = sources.Truncate(sources.Headline(f.Description), 160)
	for _, ms := range [][]cvssMetric{c.Metrics.V31, c.Metrics.V40, c.Metrics.V30, c.Metrics.V2} {
		if m, ok := pickMetric(ms); ok {
			f.CVSS, f.CVSSVector = m.CVSSData.BaseScore, m.CVSSData.VectorString
			f.Severity = finding.NormalizeSeverity(m.CVSSData.BaseSeverity + m.BaseSeverity)
			break
		}
	}
	ours, others, anywhere, onPlatform := 0, 0, 0, ""
	for _, cfg := range c.Configurations {
		platform := platformOf(selector, cfg.Operator, cfg.Nodes)
		for _, n := range cfg.Nodes {
			for _, m := range n.CPEMatch {
				switch {
				case !m.Vulnerable:
				case sources.CPEMatches(selector, m.Criteria):
					ours++
					addCPEMatch(&f, m, platform)
					if platform == "" {
						anywhere++
					} else if onPlatform == "" {
						onPlatform = platform
					}
				default:
					others++
				}
			}
		}
	}
	if ours == 0 && len(c.Configurations) > 0 {
		return f, false
	}
	// NVD often lists our CPE without bounds ("all versions") or awaits
	// analysis; the CNA's own version data is then more precise. Use the CNA
	// entries for our product (matched by product name), or all of them when
	// no other product is vulnerable in this CVE. Never another product's.
	if unbounded(f) {
		if ranges, versions := cnaVersions(selector, c, others == 0); len(ranges)+len(versions) > 0 {
			if anywhere == 0 && onPlatform != "" {
				// Vulnerable only on a platform: so are the CNA's versions.
				for _, v := range versions {
					ranges = append(ranges, finding.Range{Introduced: v, LastAffected: v})
				}
				for i := range ranges {
					ranges[i].Platform = onPlatform
				}
				versions = nil
			}
			f.Affected, f.AffectedVersions = ranges, versions
			f.Fixed = nil
			for _, r := range ranges {
				if r.Fixed != "" {
					f.Fixed = append(f.Fixed, r.Fixed)
				}
			}
		}
	}
	for _, r := range c.References {
		f.References = append(f.References, r.URL)
	}
	f.Canonicalize()
	return f, true
}

// unbounded reports whether the finding has no usable version data: none
// at all, or only "all versions" ranges.
func unbounded(f finding.Finding) bool {
	if len(f.AffectedVersions) > 0 {
		return false
	}
	for _, r := range f.Affected {
		if r != (finding.Range{}) {
			return false
		}
	}
	return true
}

// cnaVersions returns the CNA's affected versions for the selector's
// product. Entries whose product name matches the CPE product win; without
// a match, all entries are used only if allowAll (single-product CVE).
func cnaVersions(selector string, c cve, allowAll bool) ([]finding.Range, []string) {
	product := ""
	if parts := strings.Split(selector, ":"); len(parts) > 4 {
		product = normalizeName(parts[4])
	}
	matches := func(name string) bool { return product != "" && normalizeName(name) == product }
	anyMatch := false
	for _, a := range c.Affected {
		for _, d := range a.AffectedData {
			anyMatch = anyMatch || matches(d.Product)
		}
	}
	if !anyMatch && !allowAll {
		return nil, nil
	}
	var (
		ranges   []finding.Range
		versions []string
	)
	for _, a := range c.Affected {
		for _, d := range a.AffectedData {
			if anyMatch && !matches(d.Product) {
				continue
			}
			for _, v := range d.Versions {
				if v.Status != "affected" {
					continue
				}
				r, exact, ok := sources.CNAVersion(v.Version, v.LessThan, v.LessThanOrEqual, v.VersionType)
				switch {
				case !ok:
				case exact != "":
					versions = append(versions, exact)
				default:
					ranges = append(ranges, r)
				}
			}
		}
	}
	return ranges, versions
}

// normalizeName makes "Portal for ArcGIS" and "portal_for_arcgis" comparable.
func normalizeName(s string) string {
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if sep && b.Len() > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
			sep = false
			continue
		}
		sep = true
	}
	return b.String()
}

func pickMetric(ms []cvssMetric) (cvssMetric, bool) {
	for _, m := range ms {
		if m.Type == "Primary" {
			return m, true
		}
	}
	if len(ms) > 0 {
		return ms[0], true
	}
	return cvssMetric{}, false
}

// addCPEMatch adds a vulnerable CPE match of our product. With a platform
// (see platformOf), the version data holds only there; "all versions" stays
// no data.
func addCPEMatch(f *finding.Finding, m cpeMatch, platform string) {
	hasRange := m.VersionStartIncluding != "" || m.VersionStartExcluding != "" || m.VersionEndIncluding != "" || m.VersionEndExcluding != ""
	if !hasRange {
		parts := strings.Split(m.Criteria, ":")
		if len(parts) > 5 && parts[5] != "*" && parts[5] != "-" {
			if platform == "" {
				f.AffectedVersions = append(f.AffectedVersions, parts[5])
				return
			}
			m.VersionStartIncluding, m.VersionEndIncluding = parts[5], parts[5]
			hasRange = true
		}
	}
	r := finding.Range{
		Introduced:   m.VersionStartIncluding,
		Fixed:        m.VersionEndExcluding,
		LastAffected: m.VersionEndIncluding,
	}
	if m.VersionStartExcluding != "" {
		r.Introduced, r.IntroducedExclusive = m.VersionStartExcluding, true
	}
	if hasRange {
		r.Platform = platform
	}
	for _, x := range f.Affected {
		if x == r {
			return
		}
	}
	f.Affected = append(f.Affected, r)
	if r.Fixed != "" {
		f.Fixed = append(f.Fixed, r.Fixed)
	}
}

// platformOf names the platform an AND configuration limits the vulnerable
// software to: the non-vulnerable CPEs of its nodes without a vulnerable one
// ("windows", "not windows" for a negated node), or "" for none.
func platformOf(selector, operator string, nodes []node) string {
	if !strings.EqualFold(operator, "AND") {
		return ""
	}
	var names []string
	for _, n := range nodes {
		if slices.ContainsFunc(n.CPEMatch, func(m cpeMatch) bool { return m.Vulnerable }) {
			continue
		}
		for _, m := range n.CPEMatch {
			parts := strings.Split(m.Criteria, ":")
			if len(parts) < 5 || sources.CPEMatches(selector, m.Criteria) {
				continue
			}
			name := strings.ReplaceAll(parts[4], "_", " ")
			if n.Negate {
				name = "not " + name
			}
			if !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	return strings.Join(names, " or ")
}
