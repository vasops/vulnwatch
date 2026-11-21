package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/state"
)

func newValidateConfigCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "validate-config",
		Short: "Validate stack.yaml and the catalog; print resolved source selectors",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			store, err := state.Open(ctx, a.stateDB, true) // cached charts only; never writes
			if err != nil {
				return err
			}
			defer store.Close()
			products, err := a.loadProducts(ctx, cfg, store, nil)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "OK: %s with %d products\n", a.configPath, len(products))
			for _, warn := range tokenWarnings(cfg, products, a.getenv) {
				fmt.Fprintln(a.stderr, "warning:", warn)
			}
			multi := slices.ContainsFunc(products, func(p catalog.Product) bool { return p.Scope.Remote })
			for _, p := range products {
				where := ""
				if multi {
					where = p.Scope.String() + " · "
				}
				fmt.Fprintf(w, "\n%s%s %s  (exposure %s, criticality %s, min_cvss %.1f)\n", where, p.Name, p.Constraint, p.Exposure, p.Criticality, p.MinCVSS)
				if len(p.Origins) > 1 || (len(p.Origins) == 1 && p.Origins[0] != "stack.yaml") {
					fmt.Fprintf(w, "  %-20s %s\n", "from:", strings.Join(p.Origins, "; "))
				}
				for _, line := range selectorLines(cfg, p) {
					fmt.Fprintln(w, "  "+line)
				}
			}
			return nil
		},
	}
}

// tokenWarnings names the optional source tokens that are not set although
// an enabled source would use them for some product.
func tokenWarnings(cfg *config.Config, products []catalog.Product, getenv func(string) string) []string {
	s := cfg.Sources
	uses := func(sel func(catalog.Product) []string) bool {
		return slices.ContainsFunc(products, func(p catalog.Product) bool { return len(sel(p)) > 0 })
	}
	var out []string
	if s.GHSA.Enabled && getenv(s.GHSA.TokenEnv) == "" && uses(func(p catalog.Product) []string { return p.Entry.GHSA }) {
		out = append(out, s.GHSA.TokenEnv+" is not set: GHSA uses the unauthenticated GitHub API (60 requests/hour) and fails when that runs out")
	}
	if s.NVD.Enabled && s.NVD.APIKeyEnv != "" && getenv(s.NVD.APIKeyEnv) == "" && uses(func(p catalog.Product) []string { return p.Entry.NVD }) {
		out = append(out, fmt.Sprintf("%s is not set: NVD requests are spaced %s apart instead of %s", s.NVD.APIKeyEnv, s.NVD.RequestInterval, s.NVD.RequestIntervalWithKey))
	}
	return out
}

// cvelistKeys describes what CVE records match the product by: its cvelist
// names and its nvd CPEs and osv packages.
func cvelistKeys(e config.CatalogEntry) []string {
	var out []string
	for _, n := range e.CVEList {
		out = append(out, n.Vendor+" / "+n.Product)
	}
	if len(e.NVD) > 0 {
		out = append(out, "the nvd CPEs")
	}
	if len(e.OSV) > 0 {
		out = append(out, "the osv packages")
	}
	return out
}

// selectorLines describes which enabled sources will be queried for p.
func selectorLines(cfg *config.Config, p catalog.Product) []string {
	s := cfg.Sources
	var out []string
	add := func(enabled bool, name string, sel []string) {
		if len(sel) == 0 {
			return
		}
		state := ""
		if !enabled {
			state = " (source disabled)"
		}
		out = append(out, fmt.Sprintf("%-20s %s%s", name+":", strings.Join(sel, ", "), state))
	}
	add(s.GHSA.Enabled, "ghsa", p.Entry.GHSA)
	var osv []string
	for _, o := range p.Entry.OSV {
		osv = append(osv, o.Ecosystem+"/"+o.Package)
	}
	add(s.OSV.Enabled, "osv", osv)
	add(s.NVD.Enabled, "nvd", p.Entry.NVD)
	add(s.CVEList.Enabled, "cvelist", cvelistKeys(p.Entry))
	add(s.RSS.Enabled, "rss", p.Entry.RSS)
	for _, k := range s.K8sFeed.Products {
		if k == p.Name {
			add(s.K8sFeed.Enabled, "kubernetes_cve_feed", []string{"official CVE feed"})
		}
	}
	if p.OS != nil {
		add(s.OS.Enabled, "os", []string{p.OS.Name + " " + p.OS.Release + " security data (OSV), KEV/EPSS fixes only"})
	}
	if len(p.Entry.Images) > 0 {
		add(s.Trivy.Enabled, "trivy", p.Entry.Images)
	}
	if len(out) == 0 {
		out = append(out, "warning: no source selectors; nothing will be collected for this product")
	}
	return out
}
