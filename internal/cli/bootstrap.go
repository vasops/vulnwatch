package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/state"
)

func newBootstrapCmd(a *app) *cobra.Command {
	var (
		of         outputFlags
		days       int
		skipIfInit bool
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Check every product against its full advisory history; report nothing as new",
		Long: "Checks every product in the stack against all known advisories (no time window),\n" +
			"records them as seen and renders one summary: per product what affects the deployed\n" +
			"version, listed under Still open. No LLM calls. A normal `run` does the same for new\n" +
			"products and changed versions automatically; bootstrap forces it for all of them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if skipIfInit {
				done, err := a.initialized(cmd.Context())
				if err != nil {
					return err
				}
				if done {
					a.log.Info("state already initialized; bootstrap skipped", "state_db", a.stateDB)
					return nil
				}
			}
			return a.runPipeline(cmd.Context(), runParams{of: of, bootstrap: true})
		},
	}
	of.register(cmd)
	cmd.Flags().IntVar(&days, "days", 0, "ignored: bootstrap always checks the full history")
	_ = cmd.Flags().MarkDeprecated("days", "bootstrap now checks the full advisory history; drop --days")
	cmd.Flags().BoolVar(&skipIfInit, "skip-if-initialized", false,
		"do nothing if the state DB already has a successful run (safe to repeat, e.g. as a deploy hook)")
	return cmd
}

// initialized reports whether the state DB exists and has a successful run.
func (a *app) initialized(ctx context.Context) (bool, error) {
	store, err := state.Open(ctx, a.stateDB, true)
	if err != nil {
		return false, err
	}
	defer store.Close()
	_, ok, err := store.LastSuccess(ctx)
	return ok, err
}
