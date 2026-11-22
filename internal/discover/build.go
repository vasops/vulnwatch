package discover

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/helmchart"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/safe"
)

// ChartSource fetches charts (helmchart.Fetcher).
type ChartSource interface {
	Fetch(ctx context.Context, r config.HelmRelease) (*helmchart.Chart, error)
}

// Result is the discovered stack.
type Result struct {
	Context  string
	Helm     []*HelmEntry
	Products []*Product
	OS       *config.StackOS // the nodes' distribution and running kernel(s)
	// Observed has every product version found in the cluster, from
	// charts and images, for stack diff.
	Observed map[string][]string

	Unmapped       []Note // running images not in the catalog
	Ignored        int    // running images on the ignore_images list
	NoVersion      []Note // catalog images whose tag holds no version
	UnmappedCharts []string
	Warnings       []string
}

// HelmEntry is a chart deployed by Argo CD; the run reads its products from
// the chart.
type HelmEntry struct {
	Release   config.HelmRelease
	Origins   []string
	ExposedBy string
	Overrides map[string]string // product -> why versions overrides the chart
	chart     *helmchart.Chart
}

// Product is a product found outside Argo CD charts: in Helm releases,
// running images or on the nodes.
type Product struct {
	Name      string
	Versions  []string
	Origins   []string
	ExposedBy string
}

// Note is an image (or node component) worth a look.
type Note struct {
	What    string   // image reference
	Where   []string // namespace/owner
	Product string
}

type observation struct {
	product, version string
	w                Workload
	covered          bool
}

// Build turns the inventory into a stack. Charts deployed by Argo CD are
// fetched to compare the versions they declare with the images running.
func Build(ctx context.Context, cfg *config.Config, inv *Inventory, charts ChartSource, concurrency int) (*Result, error) {
	res := &Result{Context: inv.Context, Observed: map[string][]string{}, Warnings: slices.Clone(inv.Warnings)}
	products := map[string]*Product{}
	addProduct := func(name string, versions []string, origin, exposedBy string) {
		p := products[name]
		if p == nil {
			p = &Product{Name: name}
			products[name] = p
		}
		for _, v := range versions {
			p.Versions = addVersion(p.Versions, v)
		}
		if !slices.Contains(p.Origins, origin) {
			p.Origins = append(p.Origins, origin)
		}
		if p.ExposedBy == "" {
			p.ExposedBy = exposedBy
		}
	}

	obs, unmapped, ignored := observe(cfg, inv.Workloads)
	res.Ignored = ignored
	res.Unmapped = unmapped
	inNamespace := func(product, ns string) []*observation {
		var out []*observation
		for _, o := range obs {
			if o.product == product && o.w.Namespace == ns {
				o.covered = true
				out = append(out, o)
			}
		}
		return out
	}

	// Argo CD charts: one helm entry per repo/chart/version.
	entries := map[string]*HelmEntry{}
	var external int
	for _, a := range inv.Apps {
		if a.External {
			external++
			continue
		}
		m, mapped := cfg.HelmCharts[a.Chart]
		if !mapped {
			res.UnmappedCharts = append(res.UnmappedCharts, fmt.Sprintf("argocd app %s: %s %s (%s)", a.Name, a.Chart, a.Version, a.Repo))
			continue
		}
		if len(m) == 0 {
			continue // a known chart with nothing to watch (CRDs, config)
		}
		rel := config.HelmRelease{Repo: a.Repo, Chart: a.Chart, Version: a.Version}
		key := rel.Repo + "|" + rel.Chart + "|" + rel.Version
		if entries[key] == nil {
			entries[key] = &HelmEntry{Release: rel, Overrides: map[string]string{}}
			res.Helm = append(res.Helm, entries[key])
		}
		entries[key].Origins = append(entries[key].Origins, "argocd app "+a.Name)
	}
	if external > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d Argo CD chart source(s) deploy to other clusters, skipped", external))
	}
	fetchCharts(ctx, res, charts, concurrency)

	for _, a := range inv.Apps {
		if a.External {
			continue
		}
		m, mapped := cfg.HelmCharts[a.Chart]
		e := entries[a.Repo+"|"+a.Chart+"|"+a.Version]
		if !mapped || e == nil || e.chart == nil {
			continue
		}
		declared := chartVersions(e.chart, e.Release, m)
		for _, p := range config.SortedKeys(m) {
			var running []string
			for _, o := range inNamespace(p, a.Namespace) {
				running = addVersion(running, o.version)
				if e.ExposedBy == "" {
					e.ExposedBy = o.w.Exposed
				}
			}
			if len(running) == 0 {
				if declared[p] == "" {
					res.Warnings = append(res.Warnings, fmt.Sprintf("helm %s: no version for %s in the chart and no running image; set versions.%s", e.Release, p, p))
				}
				continue
			}
			if len(running) == 1 && sameVersion(running[0], declared[p]) {
				continue
			}
			if e.Release.Versions == nil {
				e.Release.Versions = map[string]string{}
			}
			e.Release.Versions[p] = match.Union(append([]string{e.Release.Versions[p]}, running...)...)
			if declared[p] != "" {
				e.Overrides[p] = "chart default " + declared[p]
			} else {
				e.Overrides[p] = "running image"
			}
		}
	}
	for _, e := range res.Helm {
		if e.chart == nil {
			continue
		}
		for p, v := range chartVersions(e.chart, e.Release, cfg.HelmCharts[e.Release.Chart]) {
			res.Observed[p] = addVersion(res.Observed[p], v)
		}
	}

	// Helm releases (helm install): the record has the chart and its
	// values but not the repository, so they become products.
	for _, r := range inv.Releases {
		origin := fmt.Sprintf("helm release %s/%s (%s %s)", r.Namespace, r.Name, r.Chart.Name, r.Chart.Version)
		if i := slices.IndexFunc(inv.Apps, func(a App) bool {
			return !a.External && a.Namespace == r.Namespace && a.ReleaseName == r.Name
		}); i >= 0 {
			// Installed with helm (bootstrap) and since managed by Argo CD,
			// which doesn't update the release record.
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s is managed by argocd app %s; its release record is stale, skipped", origin, inv.Apps[i].Name))
			continue
		}
		m, mapped := cfg.HelmCharts[r.Chart.Name]
		if !mapped {
			res.UnmappedCharts = append(res.UnmappedCharts, origin)
			continue
		}
		declared := chartVersions(r.Chart, config.HelmRelease{Chart: r.Chart.Name, Version: r.Chart.Version}, m)
		for _, p := range config.SortedKeys(m) {
			var versions []string
			exposedBy := ""
			for _, o := range inNamespace(p, r.Namespace) {
				versions = addVersion(versions, o.version)
				exposedBy = cmp.Or(exposedBy, o.w.Exposed)
			}
			if len(versions) == 0 && declared[p] != "" {
				versions = []string{declared[p]}
			}
			if len(versions) > 0 {
				addProduct(p, versions, origin, exposedBy)
			}
		}
	}

	// Images not deployed by a mapped chart.
	noVersion := map[string]*Note{}
	for _, o := range obs {
		if o.covered {
			continue
		}
		where := o.w.Namespace + "/" + o.w.Owner
		if o.version == "" {
			key := o.w.Image.String()
			if noVersion[key] == nil {
				noVersion[key] = &Note{What: key, Product: o.product}
			}
			noVersion[key].Where = append(noVersion[key].Where, where)
			continue
		}
		addProduct(o.product, []string{o.version}, o.w.Image.String()+" ("+o.w.Namespace+")", o.w.Exposed)
	}
	for _, k := range slices.Sorted(maps.Keys(noVersion)) {
		res.NoVersion = append(res.NoVersion, *noVersion[k])
	}

	nodeProducts(cfg, inv, addProduct, res)
	addOS(res, inv.Nodes)

	for _, name := range slices.Sorted(maps.Keys(products)) {
		p := products[name]
		if len(p.Versions) == 0 {
			continue
		}
		res.Products = append(res.Products, p)
		for _, v := range p.Versions {
			res.Observed[name] = addVersion(res.Observed[name], v)
		}
	}
	return res, nil
}

// fetchCharts downloads the charts of the helm entries in parallel; a
// failure is a warning (the entry is kept, the run fetches it again).
func fetchCharts(ctx context.Context, res *Result, charts ChartSource, concurrency int) {
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(concurrency, 1))
	for _, e := range res.Helm {
		g.Go(func() error {
			c, err := safe.Call(func() (*helmchart.Chart, error) { return charts.Fetch(gctx, e.Release) })
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Warnings = append(res.Warnings, err.Error()+" (kept without comparing images)")
				return nil
			}
			e.chart = c
			return nil
		})
	}
	_ = g.Wait()
	slices.Sort(res.Warnings)
}

// chartVersions are the product versions a chart declares (with the
// release's overrides); products the chart can't tell are left out.
func chartVersions(c *helmchart.Chart, r config.HelmRelease, m config.HelmChart) map[string]string {
	pvs, _ := helmchart.Versions(c, r, m)
	out := map[string]string{}
	for _, pv := range pvs {
		out[pv.Product] = pv.Version
	}
	return out
}

// observe maps each workload image to a catalog product by the catalog's
// images; the rest are returned as unmapped notes.
// Images on the ignore_images list are only counted.
func observe(cfg *config.Config, ws []Workload) ([]*observation, []Note, int) {
	images := catalog.NewImageMatcher(cfg)
	var (
		obs      []*observation
		unmapped = map[string]*Note{}
		ignored  = map[string]bool{}
	)
	for _, w := range ws {
		if p := images.Product(w.Image); p != "" {
			obs = append(obs, &observation{product: p, version: w.Image.Version(), w: w})
			continue
		}
		if images.Ignored(w.Image) {
			ignored[w.Image.String()] = true
			continue
		}
		key := w.Image.String()
		if unmapped[key] == nil {
			unmapped[key] = &Note{What: key}
		}
		unmapped[key].Where = append(unmapped[key].Where, w.Namespace+"/"+w.Owner)
	}
	var notes []Note
	for _, k := range slices.Sorted(maps.Keys(unmapped)) {
		notes = append(notes, *unmapped[k])
	}
	return obs, notes, len(ignored)
}

var componentVersion = regexp.MustCompile(`^v?\d+(?:\.\d+)*`)

// nodeProducts adds Kubernetes (API server and kubelets), the distribution
// (rke2, k3s, from the version's build metadata) and the container runtime.
func nodeProducts(cfg *config.Config, inv *Inventory, add func(string, []string, string, string), res *Result) {
	lookup := func(name string) string {
		canon, _, ok := catalog.Lookup(cfg, name)
		if !ok {
			return ""
		}
		return canon
	}
	all := []string{inv.ServerVersion}
	for _, n := range inv.Nodes {
		all = append(all, n.Kubelet)
	}
	var k8s []string
	for _, v := range all {
		core, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), "+")
		k8s = addVersion(k8s, core)
	}
	origin := fmt.Sprintf("API server and %d kubelet(s)", len(inv.Nodes))
	if p := lookup("kubernetes"); p != "" && len(k8s) > 0 {
		add(p, k8s, origin, "")
	}
	for _, dist := range []string{"rke2", "k3s"} {
		var vs []string
		for _, v := range all {
			if strings.Contains(v, "+"+dist) {
				vs = addVersion(vs, v)
			}
		}
		if len(vs) == 0 {
			continue
		}
		if p := lookup(dist); p != "" {
			add(p, vs, origin, "")
		} else {
			res.Unmapped = append(res.Unmapped, Note{What: dist + " " + strings.Join(vs, ", "), Where: []string{"nodes"}})
		}
	}
	runtimes := map[string][]string{}
	var names []string
	for _, n := range inv.Nodes {
		name, v, ok := strings.Cut(n.Runtime, "://")
		if !ok {
			continue
		}
		if _, seen := runtimes[name]; !seen {
			names = append(names, name)
		}
		runtimes[name] = addVersion(runtimes[name], cmp.Or(componentVersion.FindString(v), v))
	}
	for _, name := range names {
		if p := lookup(name); p != "" {
			add(p, runtimes[name], "container runtime on the nodes", "")
		} else {
			res.Unmapped = append(res.Unmapped, Note{What: name + " " + strings.Join(runtimes[name], ", "), Where: []string{"container runtime on the nodes"}})
		}
	}
}

// addVersion appends v unless it is empty or already listed (v1.2.3 = 1.2.3).
func addVersion(list []string, v string) []string {
	if v == "" || slices.ContainsFunc(list, func(x string) bool { return sameVersion(x, v) }) {
		return list
	}
	return append(list, v)
}

func sameVersion(a, b string) bool {
	return a != "" && strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}
