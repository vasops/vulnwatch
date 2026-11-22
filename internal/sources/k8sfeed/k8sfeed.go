// Package k8sfeed reads the official Kubernetes CVE feed (JSON Feed 1.1).
// Items carry no structured version data; the CVSS vector is parsed from the
// markdown body. Findings are attributed to the products configured in
// sources.kubernetes_cve_feed.products.
package k8sfeed

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const Name = "kubernetes_cve_feed"

type Source struct {
	cfg    config.K8sFeedSource
	client *httpx.Client

	once  sync.Once
	items []item
	err   error
}

func New(cfg config.K8sFeedSource, client *httpx.Client) *Source {
	return &Source{cfg: cfg, client: client}
}

func (s *Source) Name() string { return Name }

type item struct {
	ID            string    `json:"id"`
	URL           string    `json:"url"`
	ExternalURL   string    `json:"external_url"`
	Summary       string    `json:"summary"`
	ContentText   string    `json:"content_text"`
	DatePublished time.Time `json:"date_published"`
	DateModified  time.Time `json:"date_modified"`
}

func (s *Source) load(ctx context.Context) ([]item, error) {
	// The feed is global; fetch it once per run and share across products.
	s.once.Do(func() {
		var feed struct {
			Items []item `json:"items"`
		}
		_, s.err = s.client.GetJSON(ctx, s.cfg.URL, nil, &feed)
		s.items = feed.Items
	})
	return s.items, s.err
}

func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	if !slices.Contains(s.cfg.Products, sel.Product) {
		return nil, nil
	}
	items, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, it := range items {
		changed := it.DatePublished
		if it.DateModified.After(changed) {
			changed = it.DateModified
		}
		if changed.Before(since) || !strings.HasPrefix(it.ID, "CVE-") {
			continue
		}
		f := finding.Finding{
			ID:          it.ID,
			Product:     sel.Product,
			Title:       it.Summary,
			Description: sources.Truncate(it.ContentText, 4000),
			Published:   it.DatePublished,
			Modified:    changed,
			References:  []string{it.URL, it.ExternalURL},
			Sources:     []string{Name},
		}
		if v := finding.FindCVSS3Vector(it.ContentText); v != "" {
			if score, err := finding.CVSS3Score(v); err == nil {
				f.CVSS, f.CVSSVector = score, v
			}
		}
		f.Canonicalize()
		out = append(out, f)
	}
	return out, nil
}
