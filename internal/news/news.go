// Package news reads a few hand-picked security news feeds (Red Hat's
// security bulletins, CERT-EU's advisories) for the vulnerabilities the whole
// industry talks about, often before an advisory names one of our products,
// and finds the stack's products their headlines name. Items are not matched
// by version: each new one is posted once (see the news command).
package news

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

// Feed formats (config.NewsFormats).
const (
	FormatRSS  = "rss"  // RSS or Atom
	FormatRHSB = "rhsb" // the bulletin list on access.redhat.com, which has no feed
)

// Item is one news item.
type Item struct {
	Feed      string    // the feed's name
	ID        string    // stable within the feed: the bulletin ID, the RSS guid or link
	Title     string    // plain text
	Link      string    // absolute URL
	Published time.Time // zero when the feed gives none
	CVEs      []string  // CVE IDs in the title and summary
}

// Fetch reads one feed; items whose title matches the feed's exclude_title
// are left out.
func Fetch(ctx context.Context, c *httpx.Client, f config.NewsFeed) ([]Item, error) {
	var exclude *regexp.Regexp
	if f.ExcludeTitle != "" {
		re, err := regexp.Compile(f.ExcludeTitle)
		if err != nil {
			return nil, fmt.Errorf("exclude_title: %w", err)
		}
		exclude = re
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	if f.Format == FormatRSS {
		req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5")
	}
	body, _, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	var items []Item
	switch f.Format {
	case FormatRHSB:
		items, err = parseRHSB(body, f)
	case FormatRSS:
		items, err = parseRSS(body, f)
	default:
		err = fmt.Errorf("unknown format %q", f.Format)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", httpx.RedactURL(f.URL), err)
	}
	out := items[:0]
	for _, it := range items {
		if exclude == nil || !exclude.MatchString(it.Title) {
			out = append(out, it)
		}
	}
	return out, nil
}

func parseRSS(body []byte, f config.NewsFeed) ([]Item, error) {
	feed, err := gofeed.NewParser().ParseString(string(body))
	if err != nil {
		return nil, fmt.Errorf("parse feed: %w", err)
	}
	var out []Item
	for _, it := range feed.Items {
		link := absolute(f.URL, it.Link)
		id := it.GUID
		if id == "" {
			id = link
		}
		title := sources.StripHTML(it.Title)
		if id == "" || title == "" {
			continue
		}
		var published time.Time
		if it.PublishedParsed != nil {
			published = *it.PublishedParsed
		}
		out = append(out, Item{
			Feed: f.Name, ID: id, Title: title, Link: link, Published: published,
			CVEs: finding.ExtractCVEs(title + " " + sources.StripHTML(it.Description+" "+it.Content)),
		})
	}
	return out, nil
}

// rhsbRow is a bulletin's link in the list: the ID is in the path, the
// title (with the ID in front) is the link text.
var rhsbRow = regexp.MustCompile(`<a href="([^"]*/(RHSB-\d{4}-\d+))"[^>]*>([^<]+)</a>`)

func parseRHSB(body []byte, f config.NewsFeed) ([]Item, error) {
	var out []Item
	seen := map[string]bool{}
	for _, m := range rhsbRow.FindAllStringSubmatch(string(body), -1) {
		id := m[2]
		if seen[id] {
			continue
		}
		seen[id] = true
		title := strings.Join(strings.Fields(html.UnescapeString(m[3])), " ")
		out = append(out, Item{
			Feed: f.Name, ID: id, Title: title, Link: absolute(f.URL, m[1]), CVEs: finding.ExtractCVEs(title),
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no RHSB-YYYY-NNN links in the page (has its layout changed?)")
	}
	return out, nil
}

// absolute resolves a link against the feed URL; "" stays "".
func absolute(base, link string) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return ""
	}
	b, err := url.Parse(base)
	if err != nil {
		return link
	}
	u, err := b.Parse(link)
	if err != nil {
		return link
	}
	return u.String()
}
