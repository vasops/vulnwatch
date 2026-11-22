package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/config"
)

func newConfigCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect the effective configuration",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "dump",
		Short: "Print the fully merged effective configuration (secrets redacted)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			b, err := cfg.Dump(a.getenv)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:       "defaults config|sources",
		Short:     "Print the built-in config.yaml or sources.yaml, to start an override from",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"config", "sources"},
		RunE: func(cmd *cobra.Command, args []string) error {
			var src config.Source
			switch args[0] {
			case "config":
				src = config.BuiltinConfig
			case "sources":
				src = config.BuiltinSources
			default:
				return fmt.Errorf("want config or sources, got %q", args[0])
			}
			_, err := cmd.OutOrStdout().Write(src.Data)
			return err
		},
	})
	return cmd
}
