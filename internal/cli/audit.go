package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/pipeline"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/version"
)

func newAuditCmd(a *app) *cobra.Command {
	var (
		products       []string
		ver            string
		asJSON         bool
		failOnAffected bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Check deployed versions against the full advisory history (no state, no outputs, no LLM)",
		Long: "Checks every product in the stack (or --product) against all known advisories and\n" +
			"lists what affects the deployed version and what depends on the exact version.\n" +
			"--version checks a version that is not deployed yet, e.g. before an upgrade.",
		Example: "  vulnwatch audit\n" +
			"  vulnwatch audit --product keycloak\n" +
			"  vulnwatch audit --product keycloak --version 26.4.0 --fail-on-affected",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if ver != "" && len(products) != 1 {
				return errors.New("--version needs exactly one --product")
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			store, err := state.Open(ctx, a.stateDB, true) // caches only (charts, KEV); never writes
			if err != nil {
				return err
			}
			defer store.Close()

			var ps []catalog.Product
			if ver != "" {
				p, err := a.testProduct(ctx, cfg, products[0])
				if err != nil {
					return err
				}
				if p.Constraint, err = match.ParseConstraint(ver); err != nil {
					return fmt.Errorf("--version: %w", err)
				}
				ps = []catalog.Product{p}
			} else if ps, err = a.loadProducts(ctx, cfg, store, products); err != nil {
				return err
			}

			client := httpx.New(cfg.HTTP, version.Version, a.log)
			srcs, enr := pipeline.BuildSources(cfg, client, a.getenv, store, a.log)
			defer pipeline.CloseSources(srcs, a.log)
			// Image findings say what runs now, not what affects a version.
			srcs = slices.DeleteFunc(srcs, func(s sources.Source) bool { return s.Name() == finding.SourceTrivy })
			results, warnings, err := pipeline.Audit(ctx, srcs, enr, ps, pipeline.AdvisoryLinks(cfg), cfg.Sources.OS, cfg.HTTP.MaxConcurrency, a.log)
			if err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Fprintln(a.stderr, "warning:", w)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(results); err != nil {
					return err
				}
			} else {
				writeAudit(out, results, warnings)
			}
			affected := 0
			for _, r := range results {
				affected += r.Affected
			}
			if failOnAffected && affected > 0 {
				return fmt.Errorf("%d known %s affect the checked versions", affected, plural(affected, "vulnerability", "vulnerabilities"))
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&products, "product", nil, "limit to a product (repeatable; name or alias)")
	cmd.Flags().StringVar(&ver, "version", "", "check this version instead of the deployed one (needs one --product)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the result as JSON")
	cmd.Flags().BoolVar(&failOnAffected, "fail-on-affected", false, "exit non-zero if anything affects the checked versions (for CI)")
	return cmd
}

func writeAudit(w io.Writer, results []pipeline.AuditProduct, warnings []string) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	p("vulnwatch audit · %d %s · full advisory history\n", len(results), plural(len(results), "product", "products"))
	for _, r := range results {
		facts := []string{fmt.Sprintf("%d advisories", r.Checked)}
		switch {
		case r.Affected+r.Unknown > 0:
		case r.Complete:
			facts = append(facts, "nothing affects this version")
		default:
			facts = append(facts, "nothing found in the sources that answered")
		}
		if r.Affected > 0 {
			facts = append(facts, fmt.Sprintf("%d affected", r.Affected))
		}
		if r.Unknown > 0 {
			facts = append(facts, fmt.Sprintf("%d depend on the exact version", r.Unknown))
		}
		if r.NoVersionData > 0 {
			facts = append(facts, fmt.Sprintf("%d without version data", r.NoVersionData))
		}
		if !r.Complete {
			facts = append(facts, "INCOMPLETE: "+failedSources(warnings, r.Product)+" failed (see warnings)")
		}
		where := ""
		if r.Scope != "" {
			where = r.Scope + " · "
		}
		p("\n%s%s %s\n  %s\n", where, r.Product, strings.ReplaceAll(r.Constraint, " || ", ", "), strings.Join(facts, " · "))
		for _, v := range r.ByVersion {
			line := fmt.Sprintf("%d affected", v.Affected)
			if v.Unknown > 0 {
				line += fmt.Sprintf(" · %d depend on the exact version", v.Unknown)
			}
			p("    %s: %s\n", v.Version, line)
		}
		for _, f := range r.Findings {
			parts := []string{f.Priority, f.ID, f.Severity}
			if f.CVSS > 0 {
				parts[2] += fmt.Sprintf(" %.1f", f.CVSS)
			}
			if f.KEV {
				parts = append(parts, "[KEV]")
			}
			if f.PublicExploit {
				parts = append(parts, "[EXPLOIT]")
			}
			if len(f.Fixed) > 0 {
				parts = append(parts, "fix "+strings.Join(f.Fixed, ", "))
			} else {
				parts = append(parts, "no fix yet")
			}
			if len(f.Versions) > 0 {
				parts = append(parts, "affects "+strings.Join(f.Versions, ", "))
			} else if f.Match != string(match.Affected) {
				parts = append(parts, "(depends on exact version)")
			}
			p("  %s\n", strings.Join(parts, "  "))
			if f.Title != "" {
				p("      %s\n", f.Title)
			}
			if len(f.Advisories) > 0 {
				p("      %s\n", report.AdvisoryLine(f.Advisories))
			}
		}
	}
}

// failedSources names the sources that failed for product, from the
// collect warnings ("<source>/<product>: <error>").
func failedSources(warnings []string, product string) string {
	var out []string
	for _, w := range warnings {
		src, rest, ok := strings.Cut(w, "/")
		if ok && strings.HasPrefix(rest, product+": ") && !slices.Contains(out, src) {
			out = append(out, src)
		}
	}
	if len(out) == 0 {
		return "a source"
	}
	return strings.Join(out, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
