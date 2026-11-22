package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
)

func newCatalogCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Inspect the product catalog",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List catalog products and the sources file(s) defining them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			srcs, err := config.ReadSources(!a.noDefaults, a.sourcesPaths...)
			if err != nil {
				return err
			}
			origins := config.CatalogOrigins(srcs...)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PRODUCT\tDEFINED IN\tSTATUS\tALIASES")
			for _, name := range cfg.CatalogNames() {
				e := cfg.Catalog[name]
				origin := strings.Join(origins[name], " + ")
				status := "enabled"
				if !e.IsEnabled() {
					status = "disabled"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, origin, status, strings.Join(e.Aliases, ", "))
			}
			return tw.Flush()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show <product>",
		Short: "Print the resolved catalog entry for a product (name or alias)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			name, e, ok := catalog.Lookup(cfg, args[0])
			if !ok {
				msg := fmt.Sprintf("unknown or disabled product %q", args[0])
				if s := catalog.Suggest(cfg, args[0]); len(s) > 0 {
					msg += "; did you mean " + strings.Join(s, ", ") + "?"
				}
				return fmt.Errorf("%s", msg)
			}
			b, err := yaml.Marshal(map[string]config.CatalogEntry{name: e})
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	})
	return cmd
}
