// Package catalog resolves stack.yaml products to their source selectors.
package catalog

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/imageref"
	"github.com/vasops/vulnwatch/internal/match"
)

// Product is a stack product resolved against the catalog, with effective
// triage context.
type Product struct {
	Name        string // canonical catalog name
	Constraint  match.Constraint
	Exposure    string
	Criticality string
	MinCVSS     float64
	Entry       config.CatalogEntry
	Origins     []string        // where the versions came from (stack.yaml, helm charts)
	OS          *config.StackOS // set for the nodes' kernel (KernelProduct)
	Scope       config.Scope    // the tenant environment (or the local stack) it runs in
}

// Key identifies the product in its scope: the name for the local stack,
// "tenant/environment/name" for a tenant's. State and findings use it.
func (p Product) Key() string { return p.Scope.Prefix() + p.Name }

// KernelProduct names the product for the nodes' running kernel, from
// stack.yaml's os section: debian-13-kernel, rhel-9.4-kernel,
// sles-15-sp6-kernel.
func KernelProduct(o *config.StackOS) string {
	release := strings.Join(strings.Fields(strings.ReplaceAll(strings.ToLower(o.Release), "-", " ")), "-")
	return o.Name + "-" + release + "-kernel"
}

// Lookup finds a catalog entry by name or alias. Disabled entries are not found.
func Lookup(cfg *config.Config, name string) (string, config.CatalogEntry, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	if e, ok := cfg.Catalog[key]; ok && e.IsEnabled() {
		return key, e, true
	}
	for _, n := range cfg.CatalogNames() {
		e := cfg.Catalog[n]
		if e.IsEnabled() && slices.Contains(e.Aliases, key) {
			return n, e, true
		}
	}
	return "", config.CatalogEntry{}, false
}

// Extra is a product version derived outside stack.yaml's products map,
// e.g. from a Helm chart, with the settings of its source.
type Extra struct {
	Product string // catalog name
	Version string
	From    string
	config.ProductDefaults
}

// Resolve maps every stack product, plus extras (from Helm charts), to a
// catalog entry and applies the product-default layering: product_defaults
// from the config files, then the stack.yaml defaults block, then
// per-product settings (most specific wins). A product listed more than once
// gets the union of its versions and the strictest settings.
func Resolve(cfg *config.Config, stack *config.Stack, extras ...Extra) ([]Product, error) {
	base := layer(cfg.ProductDefaults, stack.Defaults)
	type acc struct {
		version string
		pd      config.ProductDefaults
		origins []string
	}
	var (
		errs  []error
		seen  = map[string]string{}
		specs = map[string]*acc{}
	)
	for _, name := range config.SortedKeys(stack.Products) {
		spec := stack.Products[name]
		canon, _, ok := Lookup(cfg, name)
		if !ok {
			msg := fmt.Sprintf("products.%s: unknown product", name)
			if s := Suggest(cfg, name); len(s) > 0 {
				msg += fmt.Sprintf("; did you mean %s?", strings.Join(s, ", "))
			}
			errs = append(errs, errors.New(msg+" (add it to the catalog in your sources override)"))
			continue
		}
		if prev, dup := seen[canon]; dup {
			errs = append(errs, fmt.Errorf("products.%s: same catalog product as products.%s", name, prev))
			continue
		}
		seen[canon] = name
		specs[canon] = &acc{
			version: spec.Version,
			pd:      config.ProductDefaults{MinCVSS: spec.MinCVSS, Exposure: spec.Exposure, Criticality: spec.Criticality},
			origins: []string{"stack.yaml"},
		}
	}
	for _, x := range extras {
		canon, _, ok := Lookup(cfg, x.Product)
		if !ok {
			continue // disabled in the catalog
		}
		a := specs[canon]
		if a == nil {
			specs[canon] = &acc{version: x.Version, pd: x.ProductDefaults, origins: []string{x.From}}
			continue
		}
		a.version = match.Union(a.version, x.Version)
		a.pd = strictest(a.pd, x.ProductDefaults)
		a.origins = append(a.origins, x.From)
	}
	var out []Product
	if o := stack.OS; o != nil {
		c, err := match.ParseConstraint(o.Kernel)
		if err != nil {
			errs = append(errs, fmt.Errorf("os.kernel: %w", err))
		} else {
			eff := layer(base, config.ProductDefaults{MinCVSS: o.MinCVSS, Exposure: o.Exposure, Criticality: o.Criticality})
			out = append(out, Product{
				Name: KernelProduct(o), Constraint: c, Exposure: eff.Exposure, Criticality: eff.Criticality, MinCVSS: *eff.MinCVSS,
				Origins: []string{"stack.yaml os (" + o.Name + " " + o.Release + ")"}, OS: o,
			})
		}
	}
	for _, canon := range config.SortedKeys(specs) {
		a := specs[canon]
		c, err := match.ParseConstraint(a.version)
		if err != nil {
			errs = append(errs, fmt.Errorf("products.%s: %w", canon, err))
			continue
		}
		_, entry, _ := Lookup(cfg, canon)
		eff := layer(base, a.pd)
		out = append(out, Product{
			Name:        canon,
			Constraint:  c,
			Exposure:    eff.Exposure,
			Criticality: eff.Criticality,
			MinCVSS:     *eff.MinCVSS,
			Entry:       entry,
			Origins:     a.origins,
		})
	}
	return out, errors.Join(errs...)
}

// strictest combines settings of one product deployed several times: the
// more exposed, more critical and lower-threshold value wins.
func strictest(a, b config.ProductDefaults) config.ProductDefaults {
	if b.Exposure == "internet" || a.Exposure == "" {
		a.Exposure = cmp.Or(b.Exposure, a.Exposure)
	}
	if rank(b.Criticality) > rank(a.Criticality) {
		a.Criticality = b.Criticality
	}
	if b.MinCVSS != nil && (a.MinCVSS == nil || *b.MinCVSS < *a.MinCVSS) {
		a.MinCVSS = b.MinCVSS
	}
	return a
}

func rank(criticality string) int {
	return slices.Index([]string{"low", "medium", "high"}, criticality)
}

func layer(base, over config.ProductDefaults) config.ProductDefaults {
	if over.MinCVSS != nil {
		base.MinCVSS = over.MinCVSS
	}
	if over.Exposure != "" {
		base.Exposure = over.Exposure
	}
	if over.Criticality != "" {
		base.Criticality = over.Criticality
	}
	return base
}

// Suggest returns up to three catalog names or aliases close to name.
func Suggest(cfg *config.Config, name string) []string {
	name = strings.ToLower(name)
	type cand struct {
		label string
		dist  int
	}
	var cands []cand
	for _, n := range cfg.CatalogNames() {
		e := cfg.Catalog[n]
		if !e.IsEnabled() {
			continue
		}
		best := -1
		for _, s := range append([]string{n}, e.Aliases...) {
			d := levenshtein(name, s)
			if strings.Contains(s, name) || strings.Contains(name, s) {
				d = min(d, 1)
			}
			if best < 0 || d < best {
				best = d
			}
		}
		if best <= max(2, len(name)/3) {
			cands = append(cands, cand{n, best})
		}
	}
	slices.SortStableFunc(cands, func(a, b cand) int { return a.dist - b.dist })
	var out []string
	for i := 0; i < len(cands) && i < 3; i++ {
		out = append(out, cands[i].label)
	}
	return out
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// ImageMatcher maps container images to catalog products by the catalog's
// images: an exact repository path beats a mirror that prefixes it, and a
// longer path beats a shorter one.
type ImageMatcher struct {
	patterns []imagePattern
	ignore   []string // ignore_images patterns
}

type imagePattern struct {
	ref     imageref.Ref
	product string
}

// NewImageMatcher builds the matcher from the enabled catalog entries.
func NewImageMatcher(cfg *config.Config) *ImageMatcher {
	m := &ImageMatcher{}
	for _, name := range cfg.CatalogNames() {
		e := cfg.Catalog[name]
		if !e.IsEnabled() {
			continue
		}
		for _, img := range e.Images {
			m.patterns = append(m.patterns, imagePattern{imageref.Parse(img), name})
		}
	}
	for _, g := range config.SortedKeys(cfg.IgnoreImages) {
		m.ignore = append(m.ignore, cfg.IgnoreImages[g]...)
	}
	return m
}

// Ignored reports whether an image no product claims is on the
// ignore_images list (helpers, own images, software without advisories).
func (m *ImageMatcher) Ignored(r imageref.Ref) bool {
	return slices.ContainsFunc(m.ignore, r.MatchesPattern)
}

// Product returns the catalog product of an image, or "".
func (m *ImageMatcher) Product(r imageref.Ref) string {
	best, bestLen := "", -1
	for _, p := range m.patterns {
		if !r.Matches(p.ref) {
			continue
		}
		l := len(p.ref.Path)
		if r.Path == p.ref.Path {
			l += 1 << 16
		}
		if l > bestLen {
			best, bestLen = p.product, l
		}
	}
	return best
}
