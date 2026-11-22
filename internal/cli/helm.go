package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/helmchart"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/safe"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/version"
)

// helmExtras reads every chart in stack.yaml's helm list and returns the
// product versions it deploys. Charts are fetched in parallel and cached.
func (a *app) helmExtras(ctx context.Context, cfg *config.Config, stack *config.Stack, cache sources.Cache) ([]catalog.Extra, error) {
	if len(stack.Helm) == 0 {
		return nil, nil
	}
	fetcher := helmchart.NewFetcher(httpx.New(cfg.HTTP, version.Version, a.log), cache, cfg.HTTP.MaxResponseBytes, a.log)
	results := make([][]helmchart.ProductVersion, len(stack.Helm))
	var (
		mu   sync.Mutex
		errs []string
	)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(cfg.HTTP.MaxConcurrency, 1))
	for i, r := range stack.Helm {
		g.Go(func() error {
			fail := func(err error) error {
				mu.Lock()
				defer mu.Unlock()
				errs = append(errs, fmt.Sprintf("helm[%d]: %v", i, err))
				return nil
			}
			m, mapped := cfg.HelmCharts[r.Chart]
			if !mapped {
				if len(r.Versions) == 0 {
					return fail(fmt.Errorf("chart %q has no helm_charts mapping in the sources files; add one "+
						"(helm_charts: {%s: {<catalog product>: appVersion}}) or list the versions under versions", r.Chart, r.Chart))
				}
				pv, _ := helmchart.Versions(&helmchart.Chart{}, r, nil)
				results[i] = pv
				return nil
			}
			c, err := safe.Call(func() (*helmchart.Chart, error) { return fetcher.Fetch(gctx, r) })
			if err != nil {
				if gctx.Err() != nil {
					return gctx.Err()
				}
				return fail(err)
			}
			pv, err := safe.Call(func() ([]helmchart.ProductVersion, error) { return helmchart.Versions(c, r, m) })
			if err != nil {
				return fail(err)
			}
			results[i] = pv
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "\n"))
	}
	var out []catalog.Extra
	for i, pvs := range results {
		r := stack.Helm[i]
		for _, pv := range pvs {
			out = append(out, catalog.Extra{
				Product: pv.Product, Version: pv.Version, From: pv.From,
				ProductDefaults: config.ProductDefaults{MinCVSS: r.MinCVSS, Exposure: r.Exposure, Criticality: r.Criticality},
			})
		}
	}
	return out, nil
}
