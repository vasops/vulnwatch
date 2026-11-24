// Package redhat enriches findings with Red Hat's rating, statement and
// mitigation from the Red Hat Security Data API. The statement often names
// the conditions under which a flaw is exploitable ("only servers with HTTP/2
// enabled"), which the version match can't know; Red Hat rates CVEs on the
// day they are published, often before NVD has analysed them.
//
// Ratings: GET {base_url}/cve.json?ids=CVE-a,CVE-b, batch_size per request.
// Statements: GET {base_url}/cve/{id}.json, one request per CVE, for at most
// max_details CVEs Red Hat knows, KEV-listed and higher EPSS first.
package redhat

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const (
	Name    = "redhat"
	maxText = 1500 // runes kept of a statement or mitigation
)

type Enricher struct {
	cfg    config.RedHatSource
	client *httpx.Client
}

func New(cfg config.RedHatSource, client *httpx.Client) *Enricher {
	return &Enricher{cfg: cfg, client: client}
}

func (e *Enricher) Name() string { return Name }

type rating struct {
	CVE      string `json:"CVE"`
	Severity string `json:"severity"`
}

type detail struct {
	Statement  string          `json:"statement"`
	Mitigation json.RawMessage `json:"mitigation"` // {"value": "..."}, a string or null
}

type info struct{ severity, statement, mitigation string }

func (e *Enricher) Enrich(ctx context.Context, fs []finding.Finding) error {
	var ids []string
	for i := range fs {
		for _, id := range fs[i].CVEs() {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	known := map[string]*info{}
	for batch := range slices.Chunk(ids, max(e.cfg.BatchSize, 1)) {
		q := url.Values{}
		q.Set("ids", strings.Join(batch, ","))
		q.Set("per_page", strconv.Itoa(len(batch)))
		var rs []rating
		if _, err := e.client.GetJSON(ctx, e.cfg.BaseURL+"/cve.json?"+q.Encode(), nil, &rs); err != nil {
			return err
		}
		for _, r := range rs {
			if slices.Contains(batch, r.CVE) {
				known[r.CVE] = &info{severity: strings.ToLower(r.Severity)}
			}
		}
	}

	// Statements for the CVEs Red Hat knows, the most urgent first. A failed
	// request leaves that CVE without a statement; the ratings still apply.
	var errs []error
	for _, id := range e.detailOrder(fs, known) {
		var d detail
		_, err := e.client.GetJSON(ctx, e.cfg.BaseURL+"/cve/"+url.PathEscape(id)+".json", nil, &d)
		if se, ok := errors.AsType[*httpx.StatusError](err); ok && se.Status == http.StatusNotFound {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			errs = append(errs, err)
			continue
		}
		known[id].statement = sources.Truncate(strings.TrimSpace(d.Statement), maxText)
		known[id].mitigation = sources.Truncate(strings.TrimSpace(mitigation(d.Mitigation)), maxText)
	}

	for i := range fs {
		f := &fs[i]
		for _, id := range f.CVEs() {
			in := known[id]
			if in == nil {
				continue
			}
			if finding.RedHatRank(in.severity) > finding.RedHatRank(f.RedHatSeverity) {
				f.RedHatSeverity = in.severity
			}
			f.RedHatStatement = cmp.Or(f.RedHatStatement, in.statement)
			f.RedHatMitigation = cmp.Or(f.RedHatMitigation, in.mitigation)
		}
	}
	return errors.Join(errs...)
}

// detailOrder lists the CVEs Red Hat knows, KEV-listed first, then by EPSS
// and CVSS, at most max_details.
func (e *Enricher) detailOrder(fs []finding.Finding, known map[string]*info) []string {
	type cand struct {
		id        string
		kev       bool // KEV-listed or with a public exploit
		epss, cvs float64
	}
	byID := map[string]*cand{}
	var cs []*cand
	for i := range fs {
		f := &fs[i]
		for _, id := range f.CVEs() {
			if known[id] == nil {
				continue
			}
			c := byID[id]
			if c == nil {
				c = &cand{id: id}
				byID[id] = c
				cs = append(cs, c)
			}
			c.kev = c.kev || f.KEV || f.PublicExploit
			c.epss = max(c.epss, f.EPSS)
			c.cvs = max(c.cvs, f.CVSS)
		}
	}
	slices.SortStableFunc(cs, func(a, b *cand) int {
		if a.kev != b.kev {
			if a.kev {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(b.epss, a.epss), cmp.Compare(b.cvs, a.cvs))
	})
	out := make([]string, 0, min(len(cs), e.cfg.MaxDetails))
	for _, c := range cs[:min(len(cs), e.cfg.MaxDetails)] {
		out = append(out, c.id)
	}
	return out
}

// mitigation reads Red Hat's mitigation, an object with a value or a string.
func mitigation(raw json.RawMessage) string {
	var m struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(raw, &m) == nil && m.Value != "" {
		return m.Value
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}
