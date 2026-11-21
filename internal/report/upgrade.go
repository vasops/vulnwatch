package report

import (
	"cmp"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/match"
)

// ProductUpgrade is what to upgrade a product to so its open findings with
// a known fix are fixed.
type ProductUpgrade struct {
	Product     string `json:"product"`
	Tenant      string `json:"tenant,omitempty"`
	Environment string `json:"environment,omitempty"`
	Scope       string `json:"-"`
	Constraint  string `json:"constraint"`
	// UpgradeTo is the target version, or "26.7.0 → 26.7.5, 20.0.3 → 26.7.5"
	// for products deployed in several versions; empty when nothing has a fix.
	UpgradeTo string `json:"upgrade_to,omitempty"`
	Unfixed   int    `json:"unfixed"` // open findings without any fix
	// ImageOnly counts open findings only Trivy reports: a package inside
	// the image, fixed by a newer image rather than a product version.
	ImageOnly int `json:"image_only,omitempty"`
}

// Upgrades returns one entry per product with open findings (new in this
// run or still open), sorted by product.
func (r Report) Upgrades() []ProductUpgrade {
	type acc struct {
		product, tenant, env, scope string
		constraint                  string
		fixes                       [][]string
		imageOnly                   int
	}
	per := map[string]*acc{}
	add := func(product, tenant, env, scope, constraint string, fixed []string, imageOnly bool) {
		k := tenant + "/" + env + "/" + product
		a := per[k]
		if a == nil {
			a = &acc{product: product, tenant: tenant, env: env, scope: scope, constraint: constraint}
			per[k] = a
		}
		if imageOnly {
			a.imageOnly++
			return
		}
		a.fixes = append(a.fixes, fixed)
	}
	for _, it := range r.Items() {
		add(it.Product, it.Tenant, it.Environment, it.Scope, it.Constraint, it.Fixed, it.ImageOnly)
	}
	for _, it := range r.Open {
		add(it.Product, it.Tenant, it.Environment, it.Scope, it.Constraint, it.Fixed, it.ImageOnly)
	}
	var out []ProductUpgrade
	for _, a := range per {
		u := ProductUpgrade{Product: a.product, Tenant: a.tenant, Environment: a.env, Scope: a.scope, Constraint: a.constraint, ImageOnly: a.imageOnly}
		c, err := match.ParseConstraint(a.constraint)
		if err != nil {
			continue
		}
		alts := c.Alternatives()
		var parts []string
		for _, alt := range alts {
			if len(a.fixes) == 0 {
				break
			}
			target, unfixed := match.UpgradeTarget(alt, a.fixes)
			u.Unfixed = unfixed
			if target == "" {
				continue
			}
			if len(alts) == 1 {
				parts = append(parts, target)
			} else {
				parts = append(parts, alt.String()+" → "+target)
			}
		}
		u.UpgradeTo = strings.Join(parts, ", ")
		out = append(out, u)
	}
	slices.SortFunc(out, func(a, b ProductUpgrade) int {
		return cmp.Or(strings.Compare(a.Tenant, b.Tenant), strings.Compare(a.Environment, b.Environment), strings.Compare(a.Product, b.Product))
	})
	return out
}
