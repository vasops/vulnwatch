// Package trivy reads trivy-operator's VulnerabilityReports from the cluster
// vulnwatch runs in and turns the vulnerable packages in running images into
// findings for the products those images belong to (catalog images).
package trivy

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/imageref"
	"github.com/vasops/vulnwatch/internal/kube"
	"github.com/vasops/vulnwatch/internal/sources"
)

const reportsPath = "/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports"

// pageSize keeps one page of reports (up to ~1 MiB each) small.
const pageSize = 20

// Source lists the reports once per run and serves every product from them.
type Source struct {
	images *catalog.ImageMatcher
	client func() (*kube.Client, error)
	log    *slog.Logger

	once      sync.Once
	err       error
	byProduct map[string][]finding.Finding
	unmatched []string
}

// New uses the pod's service account. client may be replaced in tests.
func New(cfg *config.Config, log *slog.Logger) *Source {
	maxSize := cfg.HTTP.MaxResponseBytes
	return &Source{
		images: catalog.NewImageMatcher(cfg),
		client: func() (*kube.Client, error) { return kube.NewInCluster(maxSize) },
		log:    log,
	}
}

// NewWithClient is New with another Kubernetes client (tests).
func NewWithClient(cfg *config.Config, c *kube.Client, log *slog.Logger) *Source {
	s := New(cfg, log)
	s.client = func() (*kube.Client, error) { return c, nil }
	return s
}

func (s *Source) Name() string { return finding.SourceTrivy }

// InCluster: Trivy's reports describe the cluster vulnwatch runs in.
func (s *Source) InCluster() bool { return true }

// Fetch returns the image findings of one product. Reports describe the
// images running now, so since is ignored.
func (s *Source) Fetch(ctx context.Context, sel sources.Selector, _ time.Time) ([]finding.Finding, error) {
	if len(sel.Entry.Images) == 0 {
		return nil, nil
	}
	s.once.Do(func() { s.err = s.load(ctx) })
	if s.err != nil {
		return nil, s.err
	}
	return slices.Clone(s.byProduct[sel.Product]), nil
}

// UnmatchedImages lists the scanned images no catalog product claims, after
// the first Fetch.
func (s *Source) UnmatchedImages() []string { return s.unmatched }

type report struct {
	Report struct {
		Registry struct {
			Server string `json:"server"`
		} `json:"registry"`
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"artifact"`
		Vulnerabilities []vulnerability `json:"vulnerabilities"`
	} `json:"report"`
}

type vulnerability struct {
	ID               string  `json:"vulnerabilityID"`
	Resource         string  `json:"resource"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion"`
	Severity         string  `json:"severity"`
	Score            float64 `json:"score"`
	Title            string  `json:"title"`
	PrimaryLink      string  `json:"primaryLink"`
	PackagePURL      string  `json:"packagePURL"`
	PublishedDate    string  `json:"publishedDate"`
	LastModifiedDate string  `json:"lastModifiedDate"`
}

func (s *Source) load(ctx context.Context) error {
	c, err := s.client()
	if err != nil {
		return fmt.Errorf("trivy-operator reports: %w", err)
	}
	reports, err := kube.List[report](ctx, c, reportsPath, "", pageSize)
	if err != nil {
		return fmt.Errorf("trivy-operator reports: %w", err)
	}
	type key struct{ product, id string }
	acc := map[key]*finding.Finding{}
	var order []key
	unmatched := map[string]bool{}
	for _, r := range reports {
		a := r.Report.Artifact
		ref := imageref.Parse(r.Report.Registry.Server + "/" + a.Repository + ":" + a.Tag)
		product := s.images.Product(ref)
		if product == "" {
			if !s.images.Ignored(ref) {
				unmatched[ref.String()] = true
			}
			continue
		}
		for _, v := range r.Report.Vulnerabilities {
			sev := finding.NormalizeSeverity(v.Severity)
			// Low and unknown severities are not worth an image finding.
			if v.ID == "" || finding.SeverityRank(sev) < finding.SeverityRank(finding.SeverityMedium) {
				continue
			}
			k := key{product, strings.ToUpper(v.ID)}
			f := acc[k]
			if f == nil {
				f = &finding.Finding{ID: k.id, Product: product, Sources: []string{finding.SourceTrivy}, Severity: sev}
				acc[k] = f
				order = append(order, k)
			}
			add(f, v, ref.String())
		}
	}
	s.byProduct = map[string][]finding.Finding{}
	for _, k := range order {
		f := acc[k]
		f.Canonicalize()
		s.byProduct[k.product] = append(s.byProduct[k.product], *f)
	}
	for img := range unmatched {
		s.unmatched = append(s.unmatched, img)
	}
	slices.Sort(s.unmatched)
	s.log.Info("trivy reports read", "reports", len(reports), "products", len(s.byProduct), "unmatched_images", len(s.unmatched))
	return nil
}

// add merges one reported package into the finding.
func add(f *finding.Finding, v vulnerability, image string) {
	p := finding.Package{Image: image, Name: v.Resource, Type: purlType(v.PackagePURL), Installed: v.InstalledVersion, Fixed: v.FixedVersion}
	if !slices.Contains(f.Packages, p) {
		f.Packages = append(f.Packages, p)
	}
	if sev := finding.NormalizeSeverity(v.Severity); finding.SeverityRank(sev) > finding.SeverityRank(f.Severity) {
		f.Severity = sev
	}
	f.CVSS = max(f.CVSS, v.Score)
	f.Title = cmp.Or(f.Title, v.Title)
	if v.PrimaryLink != "" && !slices.Contains(f.References, v.PrimaryLink) {
		f.References = append(f.References, v.PrimaryLink)
	}
	if t, err := time.Parse(time.RFC3339, v.PublishedDate); err == nil && (f.Published.IsZero() || t.Before(f.Published)) {
		f.Published = t
	}
	if t, err := time.Parse(time.RFC3339, v.LastModifiedDate); err == nil && t.After(f.Modified) {
		f.Modified = t
	}
}

// purlType is the type of a package URL ("pkg:deb/debian/libssl3@…" → deb).
func purlType(purl string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	if t == purl {
		return ""
	}
	return t
}
