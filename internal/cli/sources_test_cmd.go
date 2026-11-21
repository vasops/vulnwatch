package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/pipeline"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/version"
)

func newSourcesCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sources",
		Short: "Work with advisory sources",
	}
	var (
		product string
		days    int
		asJSON  bool
	)
	test := &cobra.Command{
		Use:   "test",
		Short: "Fetch one product's sources and print normalized findings (no LLM, outputs or state writes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			p, err := a.testProduct(cmd.Context(), cfg, product)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			store, err := state.Open(ctx, a.stateDB, true) // the cvelist index only; never writes
			if err != nil {
				return err
			}
			defer store.Close()
			client := httpx.New(cfg.HTTP, version.Version, a.log)
			srcs, _ := pipeline.BuildSources(cfg, client, a.getenv, store, a.log)
			defer pipeline.CloseSources(srcs, a.log)
			since := time.Now().AddDate(0, 0, -days)
			col, err := pipeline.Collect(ctx, srcs, []catalog.Product{p}, since, cfg.HTTP.MaxConcurrency, a.log)
			if err != nil {
				return err
			}
			raw, warnings := col.Findings, col.Warnings
			fs := finding.Dedup(raw)
			pipeline.MatchAll(fs, productsByName([]catalog.Product{p}))
			for _, w := range warnings {
				fmt.Fprintln(a.stderr, "warning:", w)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(fs)
			}
			fmt.Fprintf(out, "%s %s: %d findings since %s (%d raw)\n", p.Name, p.Constraint, len(fs), since.Format("2006-01-02"), len(raw))
			for _, f := range fs {
				fmt.Fprintf(out, "\n%s  [%s]  CVSS %.1f %s  match: %s\n", f.ID, strings.Join(f.Sources, ","), f.CVSS, f.Severity, f.Match)
				if len(f.Aliases) > 0 {
					fmt.Fprintf(out, "  aliases:  %s\n", strings.Join(f.Aliases, ", "))
				}
				fmt.Fprintf(out, "  title:    %s\n", f.Title)
				var ranges []string
				for _, r := range f.Affected {
					ranges = append(ranges, r.String())
				}
				ranges = append(ranges, f.AffectedVersions...)
				if len(ranges) > 0 {
					fmt.Fprintf(out, "  affected: %s\n", strings.Join(ranges, " | "))
				}
				if len(f.Fixed) > 0 {
					fmt.Fprintf(out, "  fixed:    %s\n", strings.Join(f.Fixed, ", "))
				}
				fmt.Fprintf(out, "  modified: %s\n", f.Modified.Format(time.RFC3339))
			}
			if len(warnings) > 0 && len(warnings) == len(srcs) {
				return errors.New("all sources failed")
			}
			return nil
		},
	}
	test.Flags().StringVar(&product, "product", "", "catalog product name or alias (required)")
	test.Flags().IntVar(&days, "days", 30, "look back this many days")
	test.Flags().BoolVar(&asJSON, "json", false, "print findings as JSON")
	_ = test.MarkFlagRequired("product")
	cmd.AddCommand(test)
	return cmd
}

// testProduct resolves a product for `sources test`: with its stack.yaml
// constraint when the stack lists it, otherwise "*" (no stack required).
func (a *app) testProduct(ctx context.Context, cfg *config.Config, name string) (catalog.Product, error) {
	canon, entry, ok := catalog.Lookup(cfg, name)
	if !ok {
		msg := fmt.Sprintf("unknown or disabled product %q", name)
		if s := catalog.Suggest(cfg, name); len(s) > 0 {
			msg += "; did you mean " + strings.Join(s, ", ") + "?"
		}
		return catalog.Product{}, errors.New(msg)
	}
	if _, err := os.Stat(a.configPath); err == nil {
		if ps, err := a.loadProducts(ctx, cfg, nil, []string{canon}); err == nil {
			return ps[0], nil
		}
	}
	c, _ := match.ParseConstraint("*")
	return catalog.Product{Name: canon, Constraint: c, Entry: entry}, nil
}
