package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/discover"
	"github.com/vasops/vulnwatch/internal/helmchart"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/kube"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/version"
)

type kubeFlags struct {
	kubeconfig, context string
}

func (f *kubeFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.kubeconfig, "kubeconfig", "", "kubeconfig file (default $KUBECONFIG, ~/.kube/config, or the in-cluster service account)")
	cmd.Flags().StringVar(&f.context, "context", "", "kubeconfig context (default the current context)")
}

// scopeFlags select a tenant's environment in stack.yaml instead of the
// local (top-level) stack.
type scopeFlags struct {
	tenant, environment string
}

func (f *scopeFlags) register(cmd *cobra.Command, what string) {
	cmd.Flags().StringVar(&f.tenant, "tenant", "", what+" the tenant's environment (tenants.<tenant>.environments.<environment>) instead of the top-level stack; needs --environment")
	cmd.Flags().StringVar(&f.environment, "environment", "", "the tenant's environment, with --tenant")
}

// path is the environment's path in stack.yaml, or nil for the local stack.
func (f scopeFlags) path() ([]string, error) {
	if (f.tenant == "") != (f.environment == "") {
		return nil, errors.New("--tenant and --environment go together")
	}
	if f.tenant == "" {
		return nil, nil
	}
	return []string{"tenants", f.tenant, "environments", f.environment}, nil
}

// matches reports whether a product belongs to the selected scope.
func (f scopeFlags) matches(s config.Scope) bool {
	if f.tenant == "" {
		return !s.Remote
	}
	return s.Remote && s.Tenant == f.tenant && s.Environment == f.environment
}

func newStackCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stack",
		Short: "Build stack.yaml from a Kubernetes cluster and check it for drift",
	}

	var (
		dk     kubeFlags
		ds     scopeFlags
		output string
	)
	disc := &cobra.Command{
		Use:   "discover",
		Short: "Write a stack.yaml from what runs in a Kubernetes cluster",
		Long: `Reads the cluster of the current (or --context) kubeconfig context and writes
a stack.yaml: Argo CD Helm charts as helm entries (with versions overrides
where the running image differs from the chart default), Helm releases,
running images matched by the catalog's images, Kubernetes, the distribution
(rke2, k3s) and the container runtime from the nodes. Workloads behind an
Ingress, a Gateway API route or a LoadBalancer/NodePort service get
exposure: internet. Images and charts vulnwatch doesn't know are listed as
comments at the end.

Needs read access to nodes, pods, cronjobs, services, ingresses,
httproutes, grpcroutes and Argo CD applications; Helm releases need read
access to Secrets and are skipped without it.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scope, err := ds.path()
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			res, err := a.discover(cmd.Context(), cfg, dk)
			if err != nil {
				return err
			}
			b, err := discover.RenderScope(res, time.Now(), scope)
			if err != nil {
				return err
			}
			stack, err := config.ParseStack(b)
			if err == nil {
				for _, sc := range stack.Scopes() {
					if _, err = catalog.Resolve(cfg, sc.Stack); err != nil {
						break
					}
				}
			}
			if err != nil {
				return fmt.Errorf("generated stack is invalid (please report this): %w", err)
			}
			a.log.Info("stack discovered", "context", res.Context, "helm", len(res.Helm), "products", len(res.Products),
				"unmapped_images", len(res.Unmapped), "unmapped_charts", len(res.UnmappedCharts))
			if output == "" || output == "-" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			return os.WriteFile(output, b, 0o644) //nolint:gosec // stack.yaml is configuration to commit and share, not a secret
		},
	}
	dk.register(disc)
	ds.register(disc, "write the stack as")
	disc.Flags().StringVarP(&output, "output", "o", "", "write to this file instead of stdout")

	var (
		fk       kubeFlags
		fs       scopeFlags
		exitCode bool
	)
	diff := &cobra.Command{
		Use:   "diff",
		Short: "Compare stack.yaml (--config) with what runs in a Kubernetes cluster",
		Long: `Discovers the cluster like stack discover and compares each product with
stack.yaml:

  drift           the cluster runs a version stack.yaml doesn't allow
  not in stack    runs in the cluster, but vulnwatch doesn't watch it
  stale           a version in a union ("20.0.3 || 26.7.0") runs nowhere in
                  the cluster; it only adds findings (fine if it runs elsewhere)
  not in cluster  declared but not found; expected for software outside
                  the cluster (GitLab on a VM, the Go toolchain)
  ok              every running version is allowed by the constraint

With --exit-code it exits 1 on drift or products not in the stack (for CI).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fs.path(); err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			declared, err := a.loadProducts(cmd.Context(), cfg, nil, nil)
			if err != nil {
				return err
			}
			// Only the stack of the cluster compared: the local one, or --tenant's environment.
			declared = slices.DeleteFunc(declared, func(p catalog.Product) bool { return !fs.matches(p.Scope) })
			res, err := a.discover(cmd.Context(), cfg, fk)
			if err != nil {
				return err
			}
			rows := discover.Diff(declared, res.Observed)
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PRODUCT\tSTACK\tCLUSTER\tSTATUS")
			counts := map[string]int{}
			for _, r := range rows {
				counts[r.Status]++
				status := r.Status
				if r.Status == discover.StatusStale {
					status += ": " + strings.Join(r.Stale, ", ")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Product, dash(r.Stack), dash(strings.Join(r.Cluster, ", ")), status)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n%d ok, %d drift, %d not in stack, %d stale, %d not in cluster (context %s)\n",
				counts[discover.StatusOK], counts[discover.StatusDrift], counts[discover.StatusNotInStack], counts[discover.StatusStale], counts[discover.StatusNotInCluster], res.Context)
			if exitCode && counts[discover.StatusDrift]+counts[discover.StatusNotInStack] > 0 {
				return errors.New("stack.yaml differs from the cluster")
			}
			return nil
		},
	}
	fk.register(diff)
	fs.register(diff, "compare the cluster with")
	diff.Flags().BoolVar(&exitCode, "exit-code", false, "exit 1 on drift or products not in the stack")

	var (
		mk     kubeFlags
		ms     scopeFlags
		key    string
		dryRun bool
	)
	merge := &cobra.Command{
		Use:   "merge <file>",
		Short: "Merge what runs in a Kubernetes cluster into a stack.yaml or Helm values file",
		Long: `Discovers the cluster like stack discover and merges the result into an
existing file, editing it in place so its formatting and comments are kept:

  - helm entries with the same repo and chart get the running version,
    versions overrides and exposure; new charts are appended
  - products get the running version when the file's constraint doesn't
    allow it (a union gets it added); new products are appended
  - exposure: internet is added where the file doesn't set exposure
  - generated_at (in the stack or tenant environment merged into) is set
    to today (UTC): the inventory's date, for the inventory age metric

Nothing is removed: a stack may cover several clusters. Run stack diff to
see stale entries. The file may be a Helm values file with the stack under a
key: "stack" is found automatically, --key sets another (dotted) path.

With --tenant and --environment the cluster is merged into that tenant's
environment (tenants.<tenant>.environments.<environment>), which is added
when missing. Run it once per cluster to build one stack.yaml for every
tenant:

  vulnwatch stack merge stack.yaml --context acme-prod --tenant acme --environment prod
  vulnwatch stack merge stack.yaml --context acme-stage --tenant acme --environment stage
  vulnwatch stack merge stack.yaml --context globex --tenant globex --environment prod`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scope, err := ms.path()
			if err != nil {
				return err
			}
			cfg, err := a.loadConfig()
			if err != nil {
				return err
			}
			src, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if err := discover.CheckScope(src, key, scope); err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			declared, err := a.declaredStack(cmd.Context(), cfg, src, key, ms)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			res, err := a.discover(cmd.Context(), cfg, mk)
			if err != nil {
				return err
			}
			out, changes, err := discover.MergeScope(cfg, src, key, scope, res, declared, time.Now())
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			for _, c := range changes {
				fmt.Fprintln(cmd.ErrOrStderr(), c)
			}
			// The file is edited in place, so what the cluster runs but
			// vulnwatch can't watch is reported here, not written into it.
			var notes bytes.Buffer
			discover.WriteNotes(&notes, res)
			if notes.Len() > 0 {
				where := "the top-level stack"
				if ms.tenant != "" {
					where = ms.tenant + "/" + ms.environment
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "\n# Not watched in %s (context %s):%s", where, res.Context, notes.String())
			}
			unchanged := bytes.Equal(out, src)
			if unchanged {
				fmt.Fprintf(cmd.ErrOrStderr(), "%s already matches context %s\n", args[0], res.Context)
			}
			if dryRun {
				_, err = cmd.OutOrStdout().Write(out)
				return err
			}
			if unchanged {
				return nil
			}
			return os.WriteFile(args[0], out, 0o644) //nolint:gosec // an existing file keeps its mode; stack.yaml is configuration to commit
		},
	}
	mk.register(merge)
	ms.register(merge, "merge into")
	merge.Flags().StringVar(&key, "key", "", `dotted path of the stack inside the file (default: the whole file, or "stack" in a Helm values file)`)
	merge.Flags().BoolVar(&dryRun, "dry-run", false, "print the merged file instead of writing it")

	cmd.AddCommand(disc, diff, merge)
	return cmd
}

// declaredStack resolves the stack inside a file (charts included) to the
// constraint of every product.
func (a *app) declaredStack(ctx context.Context, cfg *config.Config, src []byte, key string, sf scopeFlags) (map[string]match.Constraint, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	n, err := discover.StackNode(&doc, key)
	if err != nil {
		return nil, err
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return nil, err
	}
	stack, err := config.ParseStack(b)
	if err != nil {
		return nil, err
	}
	out := map[string]match.Constraint{}
	for _, sc := range stack.Scopes() {
		if !sf.matches(sc.Scope) {
			continue
		}
		extras, err := a.helmExtras(ctx, cfg, sc.Stack, nil)
		if err != nil {
			return nil, err
		}
		products, err := catalog.Resolve(cfg, sc.Stack, extras...)
		if err != nil {
			return nil, err
		}
		for _, p := range products {
			out[p.Name] = p.Constraint
		}
	}
	return out, nil
}

// discover reads the cluster and builds the stack; warnings are logged.
func (a *app) discover(ctx context.Context, cfg *config.Config, f kubeFlags) (*discover.Result, error) {
	kc, err := kube.New(f.kubeconfig, f.context, cfg.HTTP.MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	inv, err := discover.Collect(ctx, kc)
	if err != nil {
		return nil, fmt.Errorf("context %s: %w", kc.Context, err)
	}
	fetcher := helmchart.NewFetcher(httpx.New(cfg.HTTP, version.Version, a.log), nil, cfg.HTTP.MaxResponseBytes, a.log)
	res, err := discover.Build(ctx, cfg, inv, fetcher, cfg.HTTP.MaxConcurrency)
	if err != nil {
		return nil, err
	}
	for _, w := range res.Warnings {
		a.log.Warn(w)
	}
	return res, nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
