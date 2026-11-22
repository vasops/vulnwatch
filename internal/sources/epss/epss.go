// Package epss enriches findings with FIRST EPSS exploitation probabilities.
//
// API: GET {base_url}?cve=CVE-a,CVE-b. The cve parameter is capped at 2000
// characters and silently returns no data beyond that, so requests are
// chunked by count and by length.
package epss

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
)

const (
	Name        = "epss"
	maxParamLen = 1900 // API cap is 2000 characters; keep a margin
)

type Enricher struct {
	cfg    config.EPSSSource
	client *httpx.Client
}

func New(cfg config.EPSSSource, client *httpx.Client) *Enricher {
	return &Enricher{cfg: cfg, client: client}
}

func (e *Enricher) Name() string { return Name }

type response struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

type score struct{ epss, pct float64 }

func (e *Enricher) Enrich(ctx context.Context, fs []finding.Finding) error {
	var cves []string
	seen := map[string]bool{}
	for i := range fs {
		for _, id := range fs[i].CVEs() {
			if !seen[id] {
				seen[id] = true
				cves = append(cves, id)
			}
		}
	}
	scores := map[string]score{}
	for _, batch := range chunk(cves, max(e.cfg.BatchSize, 1), maxParamLen) {
		q := url.Values{}
		q.Set("cve", strings.Join(batch, ","))
		q.Set("limit", strconv.Itoa(len(batch)))
		var resp response
		if _, err := e.client.GetJSON(ctx, e.cfg.BaseURL+"?"+q.Encode(), nil, &resp); err != nil {
			return err
		}
		for _, d := range resp.Data {
			ep, err1 := strconv.ParseFloat(d.EPSS, 64)
			pc, err2 := strconv.ParseFloat(d.Percentile, 64)
			if err1 != nil || err2 != nil {
				return fmt.Errorf("epss: bad numbers for %s", d.CVE)
			}
			scores[d.CVE] = score{ep, pc}
		}
	}
	for i := range fs {
		for _, id := range fs[i].CVEs() {
			if s, ok := scores[id]; ok && s.epss > fs[i].EPSS {
				fs[i].EPSS, fs[i].EPSSPercentile = s.epss, s.pct
			}
		}
	}
	return nil
}

// chunk splits ids into batches of at most n items whose comma-joined length stays under maxLen.
func chunk(ids []string, n, maxLen int) [][]string {
	var (
		out    [][]string
		cur    []string
		curLen int
	)
	for _, id := range ids {
		add := len(id)
		if len(cur) > 0 {
			add++
		}
		if len(cur) > 0 && (len(cur) >= n || curLen+add > maxLen) {
			out, cur, curLen = append(out, cur), nil, 0
			add = len(id)
		}
		cur = append(cur, id)
		curLen += add
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}
