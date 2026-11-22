// Package rss is the generic RSS/Atom adapter for vendor feeds without an API.
// Items have no structured version data; CVE IDs are extracted from the text.
package rss

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mmcdole/gofeed"

	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const Name = "rss"

type Source struct {
	client *httpx.Client
}

func New(client *httpx.Client) *Source { return &Source{client: client} }

func (s *Source) Name() string { return Name }

func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, feedURL := range sel.Entry.RSS {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
		if err != nil {
			return out, err
		}
		req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5")
		body, _, err := s.client.Do(req)
		if err != nil {
			return out, err
		}
		feed, err := gofeed.NewParser().ParseString(string(body))
		if err != nil {
			return out, fmt.Errorf("parse %s: %w", httpx.RedactURL(feedURL), err)
		}
		for _, it := range feed.Items {
			if f, ok := toFinding(sel.Product, it, since); ok {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func toFinding(product string, it *gofeed.Item, since time.Time) (finding.Finding, bool) {
	var published, changed time.Time
	if it.PublishedParsed != nil {
		published = *it.PublishedParsed
	}
	changed = published
	if it.UpdatedParsed != nil && it.UpdatedParsed.After(changed) {
		changed = *it.UpdatedParsed
	}
	if changed.IsZero() || changed.Before(since) {
		return finding.Finding{}, false
	}
	text := sources.StripHTML(it.Description + " " + it.Content)
	id := it.Link
	if id == "" {
		id = it.GUID
	}
	f := finding.Finding{
		ID:          id,
		Product:     product,
		Title:       it.Title,
		Description: sources.Truncate(text, 4000),
		Published:   published,
		Modified:    changed,
		References:  []string{it.Link},
		Sources:     []string{Name},
	}
	// One CVE: the item describes that CVE and merges with other sources.
	// Several (release posts): keep them as related, never merge them into one.
	switch cves := finding.ExtractCVEs(it.Title + " " + text); len(cves) {
	case 0:
	case 1:
		f.Aliases = cves
	default:
		f.Related = cves
	}
	if v := finding.FindCVSS3Vector(text); v != "" {
		if score, err := finding.CVSS3Score(v); err == nil {
			f.CVSS, f.CVSSVector = score, v
		}
	}
	f.Canonicalize()
	return f, true
}
