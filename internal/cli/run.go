package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/metrics"
	"github.com/vasops/vulnwatch/internal/output"
	"github.com/vasops/vulnwatch/internal/output/html"
	"github.com/vasops/vulnwatch/internal/output/jsonout"
	pagerdutyout "github.com/vasops/vulnwatch/internal/output/pagerduty"
	slackout "github.com/vasops/vulnwatch/internal/output/slack"
	"github.com/vasops/vulnwatch/internal/output/stdout"
	teamsout "github.com/vasops/vulnwatch/internal/output/teams"
	webhookout "github.com/vasops/vulnwatch/internal/output/webhook"
	"github.com/vasops/vulnwatch/internal/pipeline"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/internal/triage"
	"github.com/vasops/vulnwatch/version"
)

var outputNames = []string{"stdout", "json", "html", "slack", "webhook", "pagerduty", "teams"}

// outputFlags are shared by run and bootstrap.
type outputFlags struct {
	outputs     string
	htmlPath    string
	jsonPath    string
	metricsFile string
}

func (f *outputFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.outputs, "output", "stdout", "comma-separated outputs: stdout,json,html,slack,webhook,pagerduty,teams")
	cmd.Flags().StringVar(&f.htmlPath, "html-path", "report.html", "target file for the html output")
	cmd.Flags().StringVar(&f.jsonPath, "json-path", "-", "target for the json output (- = stdout)")
	cmd.Flags().StringVar(&f.metricsFile, "metrics-file", "", "also write Prometheus metrics to this file (text format)")
}

func newRunCmd(a *app) *cobra.Command {
	var (
		of       outputFlags
		dryRun   bool
		since    string
		products []string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the full pipeline: collect, triage, report, persist state",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var sinceT *time.Time
			if since != "" {
				t, err := parseSince(since)
				if err != nil {
					return err
				}
				sinceT = &t
			}
			return a.runPipeline(cmd.Context(), runParams{of: of, dryRun: dryRun, since: sinceT, products: products})
		},
	}
	of.register(cmd)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "no state writes and no Slack; local outputs still render")
	cmd.Flags().StringVar(&since, "since", "", "override the window start (YYYY-MM-DD or RFC3339)")
	cmd.Flags().StringArrayVar(&products, "product", nil, "limit the run to a product (repeatable)")
	return cmd
}

func parseSince(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("--since: want YYYY-MM-DD or RFC3339, got %q", s)
}

type runParams struct {
	of        outputFlags
	dryRun    bool
	since     *time.Time
	products  []string
	bootstrap bool
}

func (a *app) runPipeline(ctx context.Context, p runParams) error {
	cfg, err := a.loadConfig()
	if err != nil {
		return err
	}
	// From here on the Pushgateway is known: a run that fails before the
	// pipeline still reports run_success=0 (the health metrics only).
	start := time.Now()
	client := httpx.New(cfg.HTTP, version.Version, a.log)
	var (
		store    *state.Store
		products []catalog.Product
	)
	failed := func(err error) error {
		a.emitMetrics(context.WithoutCancel(ctx), cfg, p, client, store, metrics.Run{
			Products: products, Err: err, Start: start, End: time.Now(),
		})
		return err
	}
	// Cheap checks first, before charts are downloaded.
	outs, err := a.buildOutputs(cfg, p.of, p.dryRun)
	if err != nil {
		return failed(err)
	}
	var triager *triage.Triager
	if cfg.Triage.Enabled && !p.bootstrap {
		key := a.getenv(cfg.Triage.APIKeyEnv)
		if key == "" {
			return failed(fmt.Errorf("%s is not set (or disable triage with `triage: {enabled: false}` in a config override, --app-config)", cfg.Triage.APIKeyEnv))
		}
		triager = triage.New(cfg.Triage, triage.NewAnthropic(cfg.Triage, key, httpx.Plain(0)), a.log)
	}

	if err := a.restrict(cfg, p.of); err != nil {
		return failed(err)
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Run.Deadline.D())
	defer cancel()
	store, err = state.Open(ctx, a.stateDB, p.dryRun)
	if err != nil {
		return failed(err)
	}
	defer store.Close()
	products, err = a.loadProducts(ctx, cfg, store, p.products)
	if err != nil {
		return failed(err)
	}

	srcs, enr := pipeline.BuildSources(cfg, client, a.getenv, store, a.log)
	defer pipeline.CloseSources(srcs, a.log)

	start = time.Now()
	rep, err := pipeline.Run(ctx, pipeline.Options{
		Config: cfg, Products: products, Sources: srcs, Enrichers: enr, Store: store,
		Triager: triager, Outputs: outs, Log: a.log, Now: time.Now,
		Since: p.since, DryRun: p.dryRun, Bootstrap: p.bootstrap, WholeStack: len(p.products) == 0,
	})
	a.emitMetrics(context.WithoutCancel(ctx), cfg, p, client, store, metrics.Run{
		Report: rep, Products: products, Err: err, Start: start, End: time.Now(),
	})
	return err
}

// emitMetrics writes --metrics-file and pushes to the Pushgateway (never on
// dry runs). Failures are logged; they don't change the run's outcome.
func (a *app) emitMetrics(ctx context.Context, cfg *config.Config, p runParams, client *httpx.Client, store *state.Store, r metrics.Run) {
	push := cfg.Metrics.PushgatewayURL != "" && !p.dryRun
	if !push && p.of.metricsFile == "" {
		return
	}
	r.Mode = "run"
	if p.bootstrap {
		r.Mode = "bootstrap"
	}
	if store != nil { // nil: the run failed before the state DB was opened
		if last, ok, err := store.LastSuccess(ctx); err == nil && ok {
			r.LastSuccess = last
		}
	}
	reg := metrics.Registry(r)
	if p.of.metricsFile != "" {
		if err := metrics.WriteFile(p.of.metricsFile, reg); err != nil {
			a.log.Error("write metrics file", "path", p.of.metricsFile, "err", err)
		}
	}
	if push {
		if err := metrics.Push(ctx, cfg.Metrics, client.HTTPClient(), reg); err != nil {
			a.log.Error("push metrics", "pushgateway", httpx.RedactURL(cfg.Metrics.PushgatewayURL), "err", httpx.RedactError(err))
			return
		}
		a.log.Info("metrics pushed", "pushgateway", httpx.RedactURL(cfg.Metrics.PushgatewayURL), "job", cfg.Metrics.Job)
	}
}

func (a *app) buildOutputs(cfg *config.Config, of outputFlags, dryRun bool) ([]output.Output, error) {
	names := splitList(of.outputs)
	if len(names) == 0 {
		return nil, fmt.Errorf("--output: at least one output is required")
	}
	for _, n := range names {
		if !slices.Contains(outputNames, n) {
			return nil, fmt.Errorf("--output: unknown output %q (want %v)", n, outputNames)
		}
	}
	if slices.Contains(names, "stdout") && slices.Contains(names, "json") && (of.jsonPath == "-" || of.jsonPath == "") {
		return nil, fmt.Errorf("--output stdout,json both write to stdout; set --json-path to a file")
	}
	var outs []output.Output
	for _, n := range names {
		switch n {
		case "stdout":
			color := false
			if f, ok := a.stdout.(*os.File); ok {
				color = stdout.IsTerminal(f)
			}
			outs = append(outs, stdout.New(a.stdout, color))
		case "json":
			outs = append(outs, jsonout.New(of.jsonPath, a.stdout))
		case "html":
			outs = append(outs, html.New(of.htmlPath))
		case "slack":
			if dryRun {
				a.log.Info("dry run: slack output skipped")
				continue
			}
			sc := cfg.Outputs.Slack
			o, err := slackout.New(sc, slackout.Settings{
				Token:        a.getenv(sc.TokenEnv),
				Channel:      a.getenv(sc.ChannelEnv),
				AlertChannel: a.getenv(sc.AlertChannelEnv),
			}, httpx.Plain(cfg.HTTP.Timeout.D()), a.log)
			if err != nil {
				return nil, err
			}
			outs = append(outs, o)
		case "webhook":
			wc := cfg.Outputs.Webhook
			headers := map[string]string{}
			for name, env := range wc.HeadersEnv {
				headers[name] = a.getenv(env)
			}
			o, err := webhookout.New(wc, webhookout.Settings{
				URL:      a.getenv(wc.URLEnv),
				AlertURL: a.getenv(wc.AlertURLEnv),
				Headers:  headers,
				DryRun:   dryRun,
			}, httpx.New(cfg.HTTP, version.Version, a.log), a.log)
			if err != nil {
				return nil, err
			}
			outs = append(outs, o)
		case "pagerduty":
			pc := cfg.Outputs.PagerDuty
			o, err := pagerdutyout.New(pc, pagerdutyout.Settings{
				RoutingKey: a.getenv(pc.RoutingKeyEnv),
				DryRun:     dryRun,
			}, httpx.New(cfg.HTTP, version.Version, a.log), a.log)
			if err != nil {
				return nil, err
			}
			outs = append(outs, o)
		case "teams":
			tc := cfg.Outputs.Teams
			o, err := teamsout.New(tc, teamsout.Settings{
				URL:      a.getenv(tc.URLEnv),
				AlertURL: a.getenv(tc.AlertURLEnv),
				DryRun:   dryRun,
			}, httpx.New(cfg.HTTP, version.Version, a.log), a.log)
			if err != nil {
				return nil, err
			}
			outs = append(outs, o)
		}
	}
	return outs, nil
}

// productsByName is a small helper for commands that print per product.
func productsByName(ps []catalog.Product) map[string]catalog.Product {
	m := map[string]catalog.Product{}
	for _, p := range ps {
		m[p.Key()] = p
	}
	return m
}
