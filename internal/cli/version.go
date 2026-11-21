package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/brand"
	"github.com/vasops/vulnwatch/version"
)

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version, commit and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			line := fmt.Sprintf("vulnwatch %s (commit %s, built %s, %s)", version.Version, version.Commit, version.Date, runtime.Version())
			if a.color() { // on a terminal: the splash; in scripts: one plain line
				_, err := fmt.Fprint(cmd.OutOrStdout(), brand.Banner(true, line))
				return err
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), line)
			return err
		},
	}
}
