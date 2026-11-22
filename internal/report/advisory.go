package report

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/vasops/vulnwatch/internal/finding"
)

// Advisory is a page about a finding at one source: the CVE record at NVD
// or the GitHub advisory.
type Advisory struct {
	Source string `json:"source"` // NVD | GitHub
	ID     string `json:"id"`
	URL    string `json:"url"`
}

// AdvisoryLinks holds the advisory page URL templates from sources.yaml
// ({id} = the CVE or GHSA ID). An empty template means no link.
type AdvisoryLinks struct {
	NVD    string // sources.nvd.detail_url
	GitHub string // sources.ghsa.detail_url
}

// For returns the advisory pages for a finding's IDs: NVD for each CVE
// ID, then GitHub for each GHSA ID. A GHSA ID's repository advisory among
// the finding's references wins over the template: many repository
// advisories never reach GitHub's global database, whose page is then a 404.
func (l AdvisoryLinks) For(ids []string, refs ...string) []Advisory {
	var out []Advisory
	add := func(source, prefix, tmpl string) {
		if tmpl == "" {
			return
		}
		for _, id := range ids {
			if !strings.HasPrefix(id, prefix) || seen(out, id) {
				continue
			}
			u := strings.ReplaceAll(tmpl, "{id}", id)
			if prefix == "GHSA-" {
				u = cmp.Or(repoAdvisory(id, refs), u)
			}
			out = append(out, Advisory{Source: source, ID: id, URL: u})
		}
	}
	add("NVD", "CVE-", l.NVD)
	add("GitHub", "GHSA-", l.GitHub)
	return out
}

// repoAdvisory finds https://github.com/<owner>/<repo>/security/advisories/<id>.
func repoAdvisory(id string, refs []string) string {
	for _, r := range refs {
		rest, ok := strings.CutPrefix(r, "https://github.com/")
		if !ok {
			continue
		}
		if parts := strings.Split(strings.TrimSuffix(rest, "/"), "/"); len(parts) == 5 &&
			parts[2] == "security" && parts[3] == "advisories" && strings.EqualFold(parts[4], id) {
			return r
		}
	}
	return ""
}

func seen(as []Advisory, id string) bool {
	for _, a := range as {
		if a.ID == id {
			return true
		}
	}
	return false
}

// advisoryURL reports whether u is one of the advisory pages.
func advisoryURL(as []Advisory, u string) bool {
	for _, a := range as {
		if a.URL == u {
			return true
		}
	}
	return false
}

// otherLinks drops references that are already advisory pages and keeps
// at most n of the rest.
func otherLinks(refs []string, as []Advisory, n int) []string {
	var out []string
	for _, r := range refs {
		if len(out) == n {
			break
		}
		if !advisoryURL(as, r) {
			out = append(out, r)
		}
	}
	return out
}

// AdvisoryLine renders advisory pages for plain text: "NVD https://… · GitHub https://…".
func AdvisoryLine(as []Advisory) string {
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = a.Source + " " + a.URL
	}
	return strings.Join(parts, " · ")
}

// PackageLine describes the image packages of a finding in one line, at
// most n of them: "libssl3 3.0.13 (fixed in 3.0.15) in docker.io/x:1; +2 more".
func PackageLine(ps []finding.Package, n int) string {
	var parts []string
	for i, p := range ps {
		if i == n {
			parts = append(parts, fmt.Sprintf("+%d more", len(ps)-n))
			break
		}
		parts = append(parts, p.String())
	}
	return strings.Join(parts, "; ")
}

// UnmatchedLine names up to n images that no product claims.
func UnmatchedLine(images []string, n int) string {
	if len(images) <= n {
		return strings.Join(images, ", ")
	}
	return strings.Join(images[:n], ", ") + fmt.Sprintf(" +%d more", len(images)-n)
}
