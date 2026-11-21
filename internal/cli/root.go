// Package cli implements the vulnwatch command line (one file per command).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/vasops/vulnwatch/internal/brand"
	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/output/stdout"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/version"
)

// Env var names for persistent flag defaults.
const (
	envStackConfig = "STACK_CONFIG"
	envSources     = "VULNWATCH_SOURCES"
	envAppConfig   = "VULNWATCH_CONFIG"
	envNoDefaults  = "VULNWATCH_NO_DEFAULTS"
	envLogLevel    = "VULNWATCH_LOG_LEVEL"
	envLogFormat   = "VULNWATCH_LOG_FORMAT"
	envLandlock    = "VULNWATCH_LANDLOCK"
	envStateDB     = "STATE_DB"
)

// app carries shared flags and dependencies for all commands.
type app struct {
	configPath   string
	sourcesPaths []string
	appConfig    []string
	noDefaults   bool
	landlock     string // landlockOff, landlockBestEffort or landlockRequire
	stateDB      string
	logLevel     string
	logFormat    string

	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	log    *slog.Logger
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	cmd := newRootCmd(stdout, stderr, getenv)
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reports whether key is set to a true value (1, true, yes).
func envBool(getenv func(string) string, key string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv(key))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func newRootCmd(out, errOut io.Writer, getenv func(string) string) *cobra.Command {
	a := &app{stdout: out, stderr: errOut, getenv: getenv}
	root := &cobra.Command{
		Use:           "vulnwatch",
		Short:         "Report new security advisories for the software we operate",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := a.setupLogging(); err != nil {
				return err
			}
			a.applyMemoryLimit()
			return nil
		},
		// No subcommand: the splash, then the usual help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprint(cmd.OutOrStdout(), brand.Banner(a.color(), version.Version))
			fmt.Fprintln(cmd.OutOrStdout())
			return cmd.Help()
		},
	}
	root.SetOut(out)
	root.SetErr(errOut)
	pf := root.PersistentFlags()
	pf.StringVar(&a.configPath, "config", envOr(getenv, envStackConfig, "./stack.yaml"), "stack config file (env "+envStackConfig+")")
	pf.StringArrayVar(&a.appConfig, "app-config", splitList(getenv(envAppConfig)),
		"config file(s) layered over the built-in one: http, run, triage, outputs, product defaults; repeat to layer more (env "+envAppConfig+", comma-separated)")
	pf.StringArrayVar(&a.sourcesPaths, "sources", splitList(getenv(envSources)),
		"sources file(s) layered over the built-in one: advisory sources, product catalog, helm chart mapping; repeat to layer more (env "+envSources+", comma-separated)")
	pf.BoolVar(&a.noDefaults, "no-defaults", envBool(getenv, envNoDefaults),
		"don't use the built-in config.yaml and sources.yaml; --app-config and --sources are then required (env "+envNoDefaults+")")
	pf.StringVar(&a.stateDB, "state-db", envOr(getenv, envStateDB, "./vulnwatch.db"), "SQLite state database (env "+envStateDB+")")
	pf.StringVar(&a.logLevel, "log-level", envOr(getenv, envLogLevel, "info"),
		"log level: "+strings.Join(logx.Levels, "|")+"; audit = what was reported and sent, plus warnings and errors (env "+envLogLevel+")")
	pf.StringVar(&a.landlock, "landlock", envOr(getenv, envLandlock, landlockBestEffort),
		"run and bootstrap: restrict the process with Landlock (Linux) to the files and ports they need; "+
			"true: where the kernel has it, require: fail the run without it, false: off (env "+envLandlock+")")
	pf.Lookup("landlock").NoOptDefVal = landlockBestEffort // a bare --landlock, as when it was a bool
	pf.StringVar(&a.logFormat, "log-format", getenv(envLogFormat), "log format: json|text (default text on a TTY, json otherwise; env "+envLogFormat+")")

	root.AddCommand(
		newRunCmd(a),
		newBootstrapCmd(a),
		newAuditCmd(a),
		newValidateConfigCmd(a),
		newCatalogCmd(a),
		newStackCmd(a),
		newConfigCmd(a),
		newSourcesCmd(a),
		newNewsCmd(a),
		newVersionCmd(a),
	)
	return root
}

// color reports whether stdout is a terminal that wants colors
// (NO_COLOR and TERM=dumb switch them off).
func (a *app) color() bool {
	f, ok := a.stdout.(*os.File)
	return ok && stdout.IsTerminal(f) && a.getenv("NO_COLOR") == "" && a.getenv("TERM") != "dumb"
}

func (a *app) setupLogging() error {
	level, err := logx.ParseLevel(a.logLevel)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	format := a.logFormat
	if format == "" {
		format = "json"
		if f, ok := a.stderr.(*os.File); ok && stdout.IsTerminal(f) {
			format = "text"
		}
	}
	if a.log, err = logx.New(a.stderr, format, level); err != nil {
		return fmt.Errorf("--log-format: %w", err)
	}
	return nil
}

func (a *app) loadConfig() (*config.Config, error) {
	return config.Load(config.LoadOptions{ConfigPaths: a.appConfig, Paths: a.sourcesPaths, Builtin: !a.noDefaults, Getenv: a.getenv})
}

// loadProducts loads stack.yaml, reads its Helm charts (cache may be nil)
// and resolves every scope (the local stack, then each tenant
// environment); only limits the result to the given product names (or
// aliases) when non-empty, in every scope.
func (a *app) loadProducts(ctx context.Context, cfg *config.Config, cache sources.Cache, only []string) ([]catalog.Product, error) {
	stack, err := config.LoadStack(a.configPath)
	if err != nil {
		return nil, err
	}
	var (
		products []catalog.Product
		errs     []error
	)
	for _, sc := range stack.Scopes() {
		wrap := func(err error) error {
			if sc.Path == "" {
				return err
			}
			return fmt.Errorf("%s: %w", sc.Path, err)
		}
		extras, err := a.helmExtras(ctx, cfg, sc.Stack, cache)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			errs = append(errs, wrap(err))
			continue
		}
		ps, err := catalog.Resolve(cfg, sc.Stack, extras...)
		if err != nil {
			errs = append(errs, wrap(err))
			continue
		}
		for i := range ps {
			ps[i].Scope = sc.Scope
		}
		products = append(products, ps...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if len(only) == 0 {
		return products, nil
	}
	var out []catalog.Product
	for _, name := range only {
		canon, _, ok := catalog.Lookup(cfg, name)
		n := len(out)
		for _, p := range products {
			if ok && p.Name == canon {
				out = append(out, p)
			}
		}
		if len(out) == n {
			return nil, fmt.Errorf("--product %s: not in %s", name, a.configPath)
		}
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
