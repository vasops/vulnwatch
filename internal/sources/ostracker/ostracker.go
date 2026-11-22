// Package ostracker watches the nodes' running kernel in the distribution's
// security data (Debian, Ubuntu, RHEL, Rocky Linux, AlmaLinux, SUSE, openSUSE
// Leap), queried through OSV with the running version(s). Only fixes
// released for the distribution release become findings, one per CVE; the
// pipeline then keeps the KEV-listed or likely exploited ones.
package ostracker

import (
	"cmp"
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/sources/osv"
)

// Name is the source name of kernel findings.
const Name = "os"

// distro describes where OSV keeps a distribution's kernel data.
type distro struct {
	ecosystem func(release string) string
	kernel    string // the kernel's (source) package
	cvePage   string // the distribution's page for a CVE; {id}
}

func major(release string) string {
	m, _, _ := strings.Cut(release, ".")
	return m
}

// suseRelease turns "15-SP6" or "15 sp6" into "15 SP6".
func suseRelease(release string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(release), "-", " "))
}

// Distros are the supported values of stack.yaml os.name.
var Distros = map[string]distro{
	"debian": {func(r string) string { return "Debian:" + major(r) }, "linux", "https://security-tracker.debian.org/tracker/{id}"},
	"ubuntu": {func(r string) string {
		if yy, mm, ok := strings.Cut(r, "."); ok && mm == "04" {
			if n, err := strconv.Atoi(yy); err == nil && n%2 == 0 {
				return "Ubuntu:" + r + ":LTS"
			}
		}
		return "Ubuntu:" + r
	}, "linux", "https://ubuntu.com/security/{id}"},
	"rhel":      {func(r string) string { return "Red Hat:enterprise_linux:" + major(r) + "::baseos" }, "kernel", "https://access.redhat.com/security/cve/{id}"},
	"rocky":     {func(r string) string { return "Rocky Linux:" + major(r) }, "kernel", ""},
	"almalinux": {func(r string) string { return "AlmaLinux:" + major(r) }, "kernel", ""},
	"sles": {func(r string) string { return "SUSE:Linux Enterprise Module for Basesystem " + suseRelease(r) },
		"kernel-default", "https://www.suse.com/security/cve/{id}/"},
	"opensuse-leap": {func(r string) string { return "openSUSE:Leap " + r }, "kernel-default", "https://www.suse.com/security/cve/{id}/"},
}

type Source struct {
	baseURL string
	client  *httpx.Client
}

// New queries OSV at baseURL (sources.osv.base_url).
func New(baseURL string, client *httpx.Client) *Source {
	return &Source{baseURL: strings.TrimRight(baseURL, "/"), client: client}
}

func (s *Source) Name() string { return Name }

type query struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type record struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Upstream  []string   `json:"upstream"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Published time.Time  `json:"published"`
	Modified  time.Time  `json:"modified"`
	Withdrawn *time.Time `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Urgency  string `json:"urgency"`  // Debian
			Priority string `json:"priority"` // Ubuntu
		} `json:"ecosystem_specific"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

var (
	cveRe      = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	severityRe = regexp.MustCompile(`(?i)\b(critical|important|moderate|low)\b`)
	epochRe    = regexp.MustCompile(`^\d+:`)
)

// Fetch returns, per CVE, the kernel fixes released for the distribution
// release that the running version(s) lack. Security data describes the
// release now, so since is ignored.
func (s *Source) Fetch(ctx context.Context, sel sources.Selector, _ time.Time) ([]finding.Finding, error) {
	o := sel.OS
	if o == nil || len(sel.Versions) == 0 {
		return nil, nil
	}
	d, ok := Distros[o.Name]
	if !ok {
		return nil, fmt.Errorf("os %q: no security data in OSV", o.Name)
	}
	eco, pkg := d.ecosystem(o.Release), cmp.Or(o.KernelPackage, d.kernel)
	byCVE := map[string]*finding.Finding{}
	var order []string
	for _, v := range sel.Versions {
		var q query
		q.Package.Ecosystem, q.Package.Name, q.Version = eco, pkg, v
		for {
			var resp struct {
				Vulns         []record `json:"vulns"`
				NextPageToken string   `json:"next_page_token"`
			}
			if err := s.client.PostJSON(ctx, s.baseURL+"/query", q, &resp); err != nil {
				return nil, fmt.Errorf("%s/%s %s: %w", eco, pkg, v, err)
			}
			for _, r := range resp.Vulns {
				for _, f := range toFindings(sel.Product, d, eco, pkg, r) {
					if prev := byCVE[f.ID]; prev != nil {
						mergeInto(prev, f)
						continue
					}
					byCVE[f.ID] = &f
					order = append(order, f.ID)
				}
			}
			if resp.NextPageToken == "" {
				break
			}
			q.PageToken = resp.NextPageToken
		}
	}
	out := make([]finding.Finding, 0, len(order))
	for _, id := range order {
		out = append(out, *byCVE[id])
	}
	return out, nil
}

// toFindings turns a record (a CVE in Debian and Ubuntu, an advisory listing
// CVEs elsewhere) into one finding per CVE, if the release has a fix.
// Records without a CVE (bug fix advisories) are skipped.
func toFindings(product string, d distro, eco, pkg string, r record) []finding.Finding {
	if r.Withdrawn != nil {
		return nil
	}
	var (
		ranges   []finding.Range
		fixed    []string
		severity = finding.SeverityUnknown
	)
	for _, a := range r.Affected {
		if !strings.EqualFold(a.Package.Ecosystem, eco) || a.Package.Name != pkg {
			continue
		}
		for _, rg := range a.Ranges {
			for _, x := range osv.EventsToRanges(rg.Events) {
				x.Introduced = epochRe.ReplaceAllString(x.Introduced, "")
				x.Fixed = epochRe.ReplaceAllString(x.Fixed, "")
				ranges = append(ranges, x)
				if x.Fixed != "" && !slices.Contains(fixed, x.Fixed) {
					fixed = append(fixed, x.Fixed)
				}
			}
		}
		if s := finding.NormalizeSeverity(cmp.Or(a.EcosystemSpecific.Urgency, a.EcosystemSpecific.Priority)); s != finding.SeverityUnknown {
			severity = s
		}
	}
	if len(fixed) == 0 {
		return nil
	}
	if m := severityRe.FindString(r.Summary); m != "" && severity == finding.SeverityUnknown {
		severity = finding.NormalizeSeverity(m)
	}
	var cves []string
	for _, c := range append(append([]string{strings.TrimPrefix(strings.TrimPrefix(r.ID, "DEBIAN-"), "UBUNTU-")}, r.Upstream...), r.Aliases...) {
		if cveRe.MatchString(c) && !slices.Contains(cves, c) {
			cves = append(cves, c)
		}
	}
	title, desc := describe(r)
	advisory := !cveRe.MatchString(strings.TrimPrefix(strings.TrimPrefix(r.ID, "DEBIAN-"), "UBUNTU-"))
	var refs []string
	if advisory {
		title = r.ID + ": " + title
		for _, ref := range r.References {
			if ref.URL != "" && len(refs) < 1 {
				refs = append(refs, ref.URL)
			}
		}
	}
	var out []finding.Finding
	for _, c := range cves {
		f := finding.Finding{
			ID: c, Product: product, Title: title, Description: desc, Severity: severity, Affected: slices.Clone(ranges), Fixed: slices.Clone(fixed),
			Published: r.Published, Modified: r.Modified, Sources: []string{Name},
		}
		if d.cvePage != "" {
			f.References = append(f.References, strings.ReplaceAll(d.cvePage, "{id}", c))
		}
		f.References = append(f.References, refs...)
		out = append(out, f)
	}
	return out
}

// mergeInto adds a CVE's fix from another record (several advisories can
// fix the same CVE).
func mergeInto(dst *finding.Finding, f finding.Finding) {
	for _, r := range f.Affected {
		if !slices.Contains(dst.Affected, r) {
			dst.Affected = append(dst.Affected, r)
		}
	}
	for _, v := range f.Fixed {
		if !slices.Contains(dst.Fixed, v) {
			dst.Fixed = append(dst.Fixed, v)
		}
	}
	for _, u := range f.References {
		if !slices.Contains(dst.References, u) {
			dst.References = append(dst.References, u)
		}
	}
	if finding.SeverityRank(f.Severity) > finding.SeverityRank(dst.Severity) {
		dst.Severity = f.Severity
	}
	if f.Modified.After(dst.Modified) {
		dst.Modified = f.Modified
	}
}

// kernelPreamble starts the Linux kernel CNA's descriptions; the line after
// it names the subsystem and the fix ("netfilter: bridge: make ... writable").
const kernelPreamble = "In the Linux kernel, the following vulnerability has been resolved:"

// describe returns a short title and the full description of a record.
func describe(r record) (title, desc string) {
	desc = strings.TrimSpace(cmp.Or(r.Details, r.Summary))
	if rest, ok := strings.CutPrefix(desc, kernelPreamble); ok {
		return firstLine(rest), desc
	}
	return firstLine(cmp.Or(r.Summary, r.Details)), desc
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	if len(line) > 200 {
		line = line[:200] + "…"
	}
	return line
}
