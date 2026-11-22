// Package helmchart reads deployed Helm charts (classic repositories and OCI
// registries) and derives catalog product versions from them: Chart.yaml
// appVersion, the chart version, image tags in values.yaml, or bundled
// subcharts. Charts are immutable per version, so parsed charts are cached
// in the state DB without expiry.
package helmchart

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

// Chart is the part of a chart archive vulnwatch needs.
type Chart struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	AppVersion string            `json:"app_version"`
	Values     map[string]any    `json:"values,omitempty"`
	Subcharts  map[string]*Chart `json:"subcharts,omitempty"`
}

// Fetcher downloads and parses charts.
type Fetcher struct {
	client *httpx.Client
	cache  sources.Cache // may be nil
	log    *slog.Logger
	// pullOCI is replaceable in tests.
	pullOCI func(ctx context.Context, ref string) ([]byte, error)
	maxSize int64
}

func NewFetcher(client *httpx.Client, cache sources.Cache, maxSize int64, log *slog.Logger) *Fetcher {
	f := &Fetcher{client: client, cache: cache, log: log, maxSize: maxSize}
	f.pullOCI = f.pullOCIRemote
	return f
}

const cachePrefix = "helmchart:v1:"

// Fetch returns the parsed chart for one release, from cache when possible.
func (f *Fetcher) Fetch(ctx context.Context, r config.HelmRelease) (*Chart, error) {
	key := cachePrefix + r.Repo + "|" + r.Chart + "|" + r.Version
	if f.cache != nil {
		if b, _, ok, err := f.cache.GetCache(ctx, key); err == nil && ok {
			var c Chart
			if err := json.Unmarshal(b, &c); err == nil {
				return &c, nil
			}
		}
	}
	var (
		archive []byte
		err     error
	)
	if strings.HasPrefix(r.Repo, "oci://") {
		ref := strings.TrimSuffix(strings.TrimPrefix(r.Repo, "oci://"), "/") + "/" + r.Chart + ":" + strings.ReplaceAll(r.Version, "+", "_")
		archive, err = f.pullOCI(ctx, ref)
	} else {
		archive, err = f.pullRepo(ctx, r)
	}
	if err != nil {
		return nil, fmt.Errorf("helm chart %s %s from %s: %w", r.Chart, r.Version, r.Repo, err)
	}
	c, err := Parse(archive, f.maxSize)
	if err != nil {
		return nil, fmt.Errorf("helm chart %s %s: %w", r.Chart, r.Version, err)
	}
	if c.Name != r.Chart {
		return nil, fmt.Errorf("helm chart %s %s: archive contains chart %q", r.Chart, r.Version, c.Name)
	}
	if f.cache != nil {
		if b, err := json.Marshal(c); err == nil {
			if err := f.cache.PutCache(ctx, key, b); err != nil {
				f.log.Warn("helm chart cache write failed", "chart", r.Chart, "err", err)
			}
		}
	}
	return c, nil
}

type repoIndex struct {
	Entries map[string][]struct {
		Version string   `yaml:"version"`
		URLs    []string `yaml:"urls"`
	} `yaml:"entries"`
}

// pullRepo finds the chart in the repository's index.yaml and downloads it.
func (f *Fetcher) pullRepo(ctx context.Context, r config.HelmRelease) ([]byte, error) {
	base, err := url.Parse(strings.TrimSuffix(r.Repo, "/") + "/")
	if err != nil {
		return nil, err
	}
	body, err := f.get(ctx, base.JoinPath("index.yaml").String())
	if err != nil {
		return nil, err
	}
	var idx repoIndex
	if err := yaml.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("parse index.yaml: %w", err)
	}
	want := strings.TrimPrefix(r.Version, "v")
	for _, e := range idx.Entries[r.Chart] {
		if strings.TrimPrefix(e.Version, "v") != want || len(e.URLs) == 0 {
			continue
		}
		u, err := base.Parse(e.URLs[0])
		if err != nil {
			return nil, err
		}
		return f.get(ctx, u.String())
	}
	if _, ok := idx.Entries[r.Chart]; !ok {
		return nil, fmt.Errorf("chart %q not found in the repository index", r.Chart)
	}
	return nil, fmt.Errorf("version %s not found in the repository index", r.Version)
}

func (f *Fetcher) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	body, _, err := f.client.Do(req)
	return body, err
}

// maxNesting is how deep subchart archives may nest (charts/x.tgz inside
// charts/y.tgz ...); real charts use one or two levels.
const maxNesting = 5

// budget is what one chart may unpack in total, nested archives included,
// so archives inside archives can't multiply maxSize.
type budget struct {
	left  int64
	max   int64
	depth int
}

// Parse reads a chart archive (.tgz), including bundled subcharts, which are
// either directories or nested archives under charts/. Everything together
// unpacks to at most maxSize bytes.
func Parse(archive []byte, maxSize int64) (*Chart, error) {
	return parse(archive, &budget{left: maxSize, max: maxSize})
}

func parse(archive []byte, b *budget) (*Chart, error) {
	if b.depth > maxNesting {
		return nil, fmt.Errorf("subchart archives nest deeper than %d levels", maxNesting)
	}
	files, err := untar(archive, b)
	if err != nil {
		return nil, err
	}
	var root string
	for name := range files {
		if dir, file := path.Split(name); file == "Chart.yaml" && strings.Count(dir, "/") == 1 {
			root = dir
		}
	}
	if root == "" {
		return nil, errors.New("no Chart.yaml at the archive root")
	}
	return parseDir(files, root, b)
}

func parseDir(files map[string][]byte, dir string, bud *budget) (*Chart, error) {
	var meta struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal(files[dir+"Chart.yaml"], &meta); err != nil {
		return nil, fmt.Errorf("%sChart.yaml: %w", dir, err)
	}
	c := &Chart{Name: meta.Name, Version: meta.Version, AppVersion: meta.AppVersion, Subcharts: map[string]*Chart{}}
	if b, ok := files[dir+"values.yaml"]; ok {
		if err := yaml.Unmarshal(b, &c.Values); err != nil {
			return nil, fmt.Errorf("%svalues.yaml: %w", dir, err)
		}
	}
	sub := dir + "charts/"
	for name, b := range files {
		rest, ok := strings.CutPrefix(name, sub)
		if !ok {
			continue
		}
		var (
			sc  *Chart
			err error
		)
		switch {
		case strings.Count(rest, "/") == 1 && strings.HasSuffix(rest, "/Chart.yaml"):
			sc, err = parseDir(files, sub+strings.TrimSuffix(rest, "Chart.yaml"), bud)
		case !strings.Contains(rest, "/") && strings.HasSuffix(rest, ".tgz"):
			bud.depth++
			sc, err = parse(b, bud)
			bud.depth--
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("subchart %s: %w", rest, err)
		}
		c.Subcharts[sc.Name] = sc
	}
	if len(c.Subcharts) == 0 {
		c.Subcharts = nil
	}
	return c, nil
}

// untar reads the YAML files and nested archives of a gzipped tarball,
// spending the budget; it refuses archives that would exceed it.
func untar(archive []byte, b *budget) (map[string][]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		name := path.Clean(h.Name)
		base := path.Base(name)
		if h.Typeflag != tar.TypeReg || (base != "Chart.yaml" && base != "values.yaml" && !strings.HasSuffix(base, ".tgz")) {
			continue
		}
		if h.Size < 0 || h.Size > b.left {
			return nil, fmt.Errorf("archive unpacks to more than %d bytes", b.max)
		}
		b.left -= h.Size
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		files[name] = b
	}
}

// ProductVersion is one product version derived from a chart.
type ProductVersion struct {
	Product string
	Version string
	From    string // human-readable origin, e.g. "kube-prometheus-stack 84.1.0 (values prometheus.prometheusSpec.image.tag)"
}

// Versions derives every mapped product's version from the chart. Overrides
// in the release replace derived versions (and may add products).
func Versions(c *Chart, r config.HelmRelease, m config.HelmChart) ([]ProductVersion, error) {
	var (
		out  []ProductVersion
		errs []error
	)
	for _, p := range config.SortedKeys(m) {
		from := m[p]
		if v, ok := r.Versions[p]; ok {
			out = append(out, ProductVersion{p, v, r.String() + " (override)"})
			continue
		}
		v, err := versionOf(c, from)
		if err != nil {
			errs = append(errs, fmt.Errorf("helm %s: %s: %w (set versions.%s in stack.yaml to override)", r, p, err, p))
			continue
		}
		out = append(out, ProductVersion{p, v, r.String() + " (" + from.String() + ")"})
	}
	for _, p := range config.SortedKeys(r.Versions) {
		if _, mapped := m[p]; !mapped {
			out = append(out, ProductVersion{p, r.Versions[p], r.String() + " (override)"})
		}
	}
	return out, errors.Join(errs...)
}

func versionOf(c *Chart, from config.VersionFrom) (string, error) {
	switch from.Kind {
	case config.FromAppVersion:
		if c.AppVersion == "" {
			return "", errors.New("chart has no appVersion")
		}
		return c.AppVersion, nil
	case config.FromChartVersion:
		return c.Version, nil
	case config.FromSubchart:
		sc := c.Subcharts[from.Subchart]
		if sc == nil {
			return "", fmt.Errorf("chart bundles no subchart %q", from.Subchart)
		}
		if from.Values == "" {
			return versionOf(sc, config.VersionFrom{Kind: config.FromAppVersion})
		}
		return versionOf(sc, config.VersionFrom{Kind: config.FromValues, Values: from.Values})
	case config.FromValues:
		return valuesTag(c.Values, from.Values)
	}
	return "", fmt.Errorf("unknown version source %q", from.Kind)
}

// versionPrefix is the leading version of an image tag such as
// "v3.9.1-distroless" or "17.4-7-bullseye".
var versionPrefix = regexp.MustCompile(`^v?\d+(\.\d+)*`)

// preRelease is a pre-release suffix after the version prefix ("-rc1",
// "-beta.2"), kept; distro and variant suffixes ("-alpine") are not.
var preRelease = regexp.MustCompile(`^-?(?i:alpha|beta|rc|preview|pre)(?:\.?\d+)*\b`)

func valuesTag(values map[string]any, dotted string) (string, error) {
	var cur any = values
	for _, k := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("values %s: %q is not a mapping", dotted, k)
		}
		if cur, ok = m[k]; !ok {
			return "", fmt.Errorf("values %s: key %q not found", dotted, k)
		}
	}
	var s string
	switch v := cur.(type) {
	case nil:
	case string:
		s = strings.TrimSpace(v)
	case int, float64:
		s = fmt.Sprint(v)
	default:
		return "", fmt.Errorf("values %s is not a string", dotted)
	}
	switch {
	case s == "":
		return "", fmt.Errorf("values %s is empty (the image default is decided at runtime)", dotted)
	case strings.Contains(s, "{{"):
		return "", fmt.Errorf("values %s is a template (%s); map it to chartVersion or appVersion instead", dotted, s)
	}
	s, _, _ = strings.Cut(s, "@") // drop a digest
	if m := versionPrefix.FindString(s); m != "" {
		return m + preRelease.FindString(s[len(m):]), nil
	}
	return s, nil
}
