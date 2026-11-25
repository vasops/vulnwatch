package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/defaults"
	"github.com/vasops/vulnwatch/internal/imageref"
)

// Env var names that override single triage values (precedence: docs/configuration.md).
const (
	EnvClaudeModel    = "CLAUDE_MODEL"
	EnvClaudeEffort   = "CLAUDE_EFFORT"
	EnvReportLanguage = "REPORT_LANGUAGE"
	EnvMaxLLMFindings = "MAX_LLM_FINDINGS"
)

// LoadOptions controls Load.
type LoadOptions struct {
	// ConfigPaths are the config files (--app-config): how vulnwatch runs
	// (http, run, triage, outputs, product_defaults). See defaults/config.yaml.
	ConfigPaths []string
	// Paths are the sources files (--sources): where to look (sources,
	// catalog, helm_charts). See defaults/sources.yaml.
	// Each kind is deep-merged in order; at least one of each is required.
	Paths []string
	// Builtin starts from the defaults built into the binary
	// (BuiltinConfig, BuiltinSources) and layers the files over them; the
	// files are then optional.
	Builtin bool
	// Getenv looks up environment variables; defaults to os.Getenv.
	Getenv func(string) string
}

// Source is one config document and the name used in error messages.
type Source struct {
	Name string
	Data []byte
}

// BuiltinConfig and BuiltinSources are defaults/config.yaml and
// defaults/sources.yaml as built into the binary.
var (
	BuiltinConfig  = Source{Name: "built-in config.yaml", Data: defaults.Config}
	BuiltinSources = Source{Name: "built-in sources.yaml", Data: defaults.Sources}
)

// Top-level keys of each file kind. version is allowed in both.
var (
	configKeys  = []string{"version", "http", "run", "triage", "outputs", "metrics", "product_defaults"}
	sourcesKeys = []string{"version", "sources", "catalog", "helm_charts", "ignore_images"}
)

// ReadSources reads sources files in order, after the built-in one if builtin.
func ReadSources(builtin bool, paths ...string) ([]Source, error) {
	return readFiles(builtin, BuiltinSources, "sources file", "--sources or set VULNWATCH_SOURCES", paths)
}

// ReadConfigs reads config files in order, after the built-in one if builtin.
func ReadConfigs(builtin bool, paths ...string) ([]Source, error) {
	return readFiles(builtin, BuiltinConfig, "config file", "--app-config or set VULNWATCH_CONFIG", paths)
}

func readFiles(builtin bool, base Source, what, hint string, paths []string) ([]Source, error) {
	srcs := make([]Source, 0, len(paths)+1)
	if builtin {
		srcs = append(srcs, base)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // reading the files the operator names is the point
		if err != nil {
			return nil, fmt.Errorf("read %s: %w (pass %s)", what, err, hint)
		}
		srcs = append(srcs, Source{Name: p, Data: b})
	}
	return srcs, nil
}

// checkKeys rejects top-level keys that belong in the other kind of file.
func checkKeys(docs []Source, allowed, other []string, otherFile string) error {
	var errs []error
	for _, d := range docs {
		m, err := decodeMap(d.Data, d.Name)
		if err != nil {
			return err
		}
		for _, k := range SortedKeys(m) {
			switch {
			case slices.Contains(allowed, k):
			case slices.Contains(other, k):
				errs = append(errs, fmt.Errorf("%s: %q belongs in %s, not here", d.Name, k, otherFile))
			default:
				errs = append(errs, fmt.Errorf("%s: unknown top-level key %q (allowed: %s)", d.Name, k, strings.Join(allowed, ", ")))
			}
		}
	}
	return errors.Join(errs...)
}

// Load returns the effective configuration: config files and sources files,
// each deep-merged in order, then single-value env overrides, then validation.
func Load(opts LoadOptions) (*Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	if !opts.Builtin && len(opts.ConfigPaths) == 0 {
		return nil, errors.New("no config file given and the built-in defaults are off: pass --app-config or set VULNWATCH_CONFIG (vulnwatch config defaults config prints the built-in one)")
	}
	if !opts.Builtin && len(opts.Paths) == 0 {
		return nil, errors.New("no sources file given and the built-in defaults are off: pass --sources or set VULNWATCH_SOURCES (vulnwatch config defaults sources prints the built-in one)")
	}
	cfgs, err := ReadConfigs(opts.Builtin, opts.ConfigPaths...)
	if err != nil {
		return nil, err
	}
	srcs, err := ReadSources(opts.Builtin, opts.Paths...)
	if err != nil {
		return nil, err
	}
	if err := errors.Join(
		checkKeys(cfgs, configKeys, sourcesKeys, "the sources file (--sources)"),
		checkKeys(srcs, sourcesKeys, configKeys, "the config file (--app-config)"),
	); err != nil {
		return nil, err
	}
	cfg, err := Merge(append(cfgs, srcs...)...)
	if err != nil {
		return nil, err
	}
	if err := applyEnv(cfg, getenv); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Merge deep-merges the documents in order and strictly decodes the result.
// Maps merge key by key (later wins); lists and scalars replace.
func Merge(docs ...Source) (*Config, error) {
	merged := map[string]any{}
	for _, d := range docs {
		if len(bytes.TrimSpace(d.Data)) == 0 {
			continue
		}
		// Strict-decode each document on its own first so unknown keys are
		// reported against the file that contains them.
		if err := strictDecode(d.Data, &Config{}); err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name, err)
		}
		m, err := decodeMap(d.Data, d.Name)
		if err != nil {
			return nil, err
		}
		if v, ok := m["version"]; ok && v != SchemaVersion {
			return nil, fmt.Errorf("%s: unsupported version %v (want %d)", d.Name, v, SchemaVersion)
		}
		merged = deepMerge(merged, m)
	}
	out, err := yaml.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("re-encode merged config: %w", err)
	}
	var cfg Config
	if err := strictDecode(out, &cfg); err != nil {
		return nil, fmt.Errorf("merged config: %w", err)
	}
	return &cfg, nil
}

// CatalogOrigins maps each catalog product to the names of the documents
// that define or modify it, in merge order.
func CatalogOrigins(docs ...Source) map[string][]string {
	out := map[string][]string{}
	for _, d := range docs {
		var doc struct {
			Catalog map[string]any `yaml:"catalog"`
		}
		if yaml.Unmarshal(d.Data, &doc) != nil {
			continue
		}
		for name := range doc.Catalog {
			out[name] = append(out[name], d.Name)
		}
	}
	return out
}

func decodeMap(b []byte, what string) (map[string]any, error) {
	m := map[string]any{}
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", what, err)
	}
	return m, nil
}

func strictDecode(b []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	// An empty document decodes to io.EOF, which is fine.
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func deepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, ov := range over {
		bv, exists := out[k]
		bm, bIsMap := bv.(map[string]any)
		om, oIsMap := ov.(map[string]any)
		if exists && bIsMap && oIsMap {
			out[k] = deepMerge(bm, om)
			continue
		}
		out[k] = ov
	}
	return out
}

func applyEnv(cfg *Config, getenv func(string) string) error {
	if v := getenv(EnvClaudeModel); v != "" {
		cfg.Triage.Model = v
	}
	if v := getenv(EnvClaudeEffort); v != "" {
		cfg.Triage.Effort = v
	}
	if v := getenv(EnvReportLanguage); v != "" {
		cfg.Triage.Language = v
	}
	if v := getenv(EnvMaxLLMFindings); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("%s: want a non-negative integer, got %q", EnvMaxLLMFindings, v)
		}
		cfg.Triage.MaxFindings = n
	}
	return nil
}

// Validate checks the merged configuration for consistency.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Version != SchemaVersion {
		add("version: unsupported %d (want %d)", c.Version, SchemaVersion)
	}
	if c.HTTP.Timeout <= 0 {
		add("http.timeout must be > 0")
	}
	if c.HTTP.MaxConcurrency <= 0 {
		add("http.max_concurrency must be > 0")
	}
	if c.HTTP.Retries < 0 {
		add("http.retries must be >= 0")
	}
	if c.Run.Deadline <= 0 {
		add("run.deadline must be > 0")
	}
	if c.Run.RetryFailedAfter < 0 || c.Run.RetryFailedAfter >= c.Run.Deadline {
		add("run.retry_failed_after must be >= 0 and below run.deadline")
	}
	s := c.Sources
	need := func(enabled bool, field, value string) {
		if enabled && strings.TrimSpace(value) == "" {
			add("%s is required when the source is enabled", field)
		}
	}
	need(s.GHSA.Enabled, "sources.ghsa.base_url", s.GHSA.BaseURL)
	need(s.GHSA.Enabled, "sources.ghsa.token_env", s.GHSA.TokenEnv)
	need(s.OSV.Enabled, "sources.osv.base_url", s.OSV.BaseURL)
	need(s.NVD.Enabled, "sources.nvd.base_url", s.NVD.BaseURL)
	need(s.K8sFeed.Enabled, "sources.kubernetes_cve_feed.url", s.K8sFeed.URL)
	need(s.KEV.Enabled, "sources.kev.url", s.KEV.URL)
	need(s.EPSS.Enabled, "sources.epss.base_url", s.EPSS.BaseURL)
	need(s.Exploits.Enabled, "sources.exploits.metasploit_url or sources.exploits.nuclei_url", strings.TrimSpace(s.Exploits.MetasploitURL)+strings.TrimSpace(s.Exploits.NucleiURL))
	need(s.CVEList.Enabled, "sources.cvelist.releases_url", s.CVEList.ReleasesURL)
	need(s.CVEList.Enabled, "sources.cvelist.records_url", s.CVEList.RecordsURL)
	if s.NVD.MaxInFlight < 0 || s.NVD.Timeout < 0 || s.NVD.Budget < 0 {
		add("sources.nvd.max_in_flight, sources.nvd.timeout and sources.nvd.budget must be >= 0")
	}
	if s.NVD.Budget > 0 && s.NVD.Budget >= c.Run.Deadline {
		add("sources.nvd.budget must be below run.deadline: a slow NVD must not use up the run")
	}
	if s.NVD.Enabled && s.NVD.MaxWindow <= 0 {
		add("sources.nvd.max_window must be > 0")
	}
	if s.EPSS.Enabled && s.EPSS.BatchSize <= 0 {
		add("sources.epss.batch_size must be > 0")
	}
	need(s.RedHat.Enabled, "sources.redhat.base_url", s.RedHat.BaseURL)
	if s.RedHat.Enabled && s.RedHat.BatchSize <= 0 {
		add("sources.redhat.batch_size must be > 0")
	}
	if s.RedHat.MaxDetails < 0 {
		add("sources.redhat.max_details must be >= 0")
	}
	need(s.OS.Enabled, "sources.osv.base_url (used by sources.os)", s.OSV.BaseURL)
	if s.OS.MinEPSS < 0 || s.OS.MinEPSS > 1 {
		add("sources.os.min_epss must be between 0 and 1")
	}
	if s.Trivy.Enabled {
		for _, f := range [][2]string{{"min_severity", s.Trivy.MinSeverity}, {"min_severity_internet", s.Trivy.MinSeverityInternet}} {
			if !slices.Contains(TrivySeverities, f[1]) {
				add("sources.trivy.%s: want one of %v, got %q", f[0], TrivySeverities, f[1])
			}
		}
		if s.Trivy.MinEPSS < 0 || s.Trivy.MinEPSS > 1 {
			add("sources.trivy.min_epss must be between 0 and 1")
		}
	}
	if c.Triage.Enabled {
		need(true, "triage.model", c.Triage.Model)
		need(true, "triage.api_key_env", c.Triage.APIKeyEnv)
		if c.Triage.Effort != "" && !slices.Contains(Efforts, c.Triage.Effort) {
			add("triage.effort: %q is not one of %v", c.Triage.Effort, Efforts)
		}
		if c.Triage.BatchSize <= 0 {
			add("triage.batch_size must be > 0")
		}
		if c.Triage.MaxTokens <= 0 {
			add("triage.max_tokens must be > 0")
		}
	}
	if c.Metrics.PushgatewayURL != "" {
		if !strings.HasPrefix(c.Metrics.PushgatewayURL, "http://") && !strings.HasPrefix(c.Metrics.PushgatewayURL, "https://") {
			add("metrics.pushgateway_url: want http(s)://…, got %q", c.Metrics.PushgatewayURL)
		}
		need(true, "metrics.job", c.Metrics.Job)
		if c.Metrics.Timeout <= 0 {
			add("metrics.timeout must be > 0")
		}
	}
	if err := c.ProductDefaults.validate("product_defaults", true); err != nil {
		errs = append(errs, err)
	}

	owner := map[string]string{}
	for _, name := range c.CatalogNames() {
		e := c.Catalog[name]
		if prev, dup := owner[name]; dup {
			add("catalog.%s: name collides with alias of %s", name, prev)
		}
		owner[name] = name
		for _, a := range e.Aliases {
			if prev, dup := owner[a]; dup && prev != name {
				add("catalog.%s: alias %q already used by %s", name, a, prev)
			}
			owner[a] = name
		}
		for i, p := range e.OSV {
			if p.Ecosystem == "" || p.Package == "" {
				add("catalog.%s.osv[%d]: ecosystem and package are required", name, i)
			}
		}
		for i, n := range e.CVEList {
			if strings.TrimSpace(n.Vendor) == "" || strings.TrimSpace(n.Product) == "" {
				add("catalog.%s.cvelist[%d]: vendor and product are required", name, i)
			}
		}
		for i, cpe := range e.NVD {
			if !strings.HasPrefix(cpe, "cpe:2.3:") {
				add("catalog.%s.nvd[%d]: %q is not a CPE 2.3 match string", name, i, cpe)
			}
		}
		for i, r := range e.GHSA {
			if parts := strings.Split(r, "/"); len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				add("catalog.%s.ghsa[%d]: %q is not owner/repo", name, i, r)
			}
		}
	}
	imageOwner := map[string]string{}
	for _, name := range c.CatalogNames() {
		for i, img := range c.Catalog[name].Images {
			r := imageref.Parse(img)
			switch {
			case strings.TrimSpace(img) == "":
				add("catalog.%s.images[%d]: empty", name, i)
			case r.Tag != "" || r.Digest != "":
				add("catalog.%s.images[%d]: %q: want a repository without tag or digest", name, i, img)
			case imageOwner[r.Path] != "" && imageOwner[r.Path] != name:
				add("catalog.%s.images[%d]: %s is already an image of %s", name, i, img, imageOwner[r.Path])
			default:
				imageOwner[r.Path] = name
			}
		}
	}
	if s.News.Enabled {
		seen := map[string]bool{}
		for i, f := range s.News.Feeds {
			switch {
			case strings.TrimSpace(f.Name) == "":
				add("sources.news.feeds[%d].name is required", i)
			case seen[f.Name]:
				add("sources.news.feeds[%d].name: %q is used twice (it keys what was already posted)", i, f.Name)
			}
			seen[f.Name] = true
			if !strings.HasPrefix(f.URL, "https://") && !strings.HasPrefix(f.URL, "http://") {
				add("sources.news.feeds[%d].url: want http(s)://…, got %q", i, f.URL)
			}
			if !slices.Contains(NewsFormats, f.Format) {
				add("sources.news.feeds[%d].format: want one of %v, got %q", i, NewsFormats, f.Format)
			}
			if _, err := regexp.Compile(f.ExcludeTitle); err != nil {
				add("sources.news.feeds[%d].exclude_title: %v", i, err)
			}
		}
	}
	for _, p := range s.K8sFeed.Products {
		if _, ok := c.Catalog[p]; !ok {
			add("sources.kubernetes_cve_feed.products: %q is not a catalog product", p)
		}
	}
	if err := c.validateHelmCharts(); err != nil {
		errs = append(errs, err)
	}
	for _, g := range SortedKeys(c.IgnoreImages) {
		for i, img := range c.IgnoreImages[g] {
			r := imageref.Parse(img)
			switch {
			case strings.TrimSpace(img) == "":
				add("ignore_images.%s[%d]: empty", g, i)
			case r.Tag != "" || r.Digest != "":
				add("ignore_images.%s[%d]: %q: want a repository pattern without tag or digest", g, i, img)
			}
		}
	}
	return errors.Join(errs...)
}

func (p ProductDefaults) validate(path string, requireAll bool) error {
	var errs []error
	if p.MinCVSS != nil && (*p.MinCVSS < 0 || *p.MinCVSS > 10) {
		errs = append(errs, fmt.Errorf("%s.min_cvss must be between 0 and 10", path))
	}
	if p.Exposure != "" && !slices.Contains(Exposures, p.Exposure) {
		errs = append(errs, fmt.Errorf("%s.exposure: %q is not one of %v", path, p.Exposure, Exposures))
	}
	if p.Criticality != "" && !slices.Contains(Criticalities, p.Criticality) {
		errs = append(errs, fmt.Errorf("%s.criticality: %q is not one of %v", path, p.Criticality, Criticalities))
	}
	if requireAll && (p.MinCVSS == nil || p.Exposure == "" || p.Criticality == "") {
		errs = append(errs, fmt.Errorf("%s: min_cvss, exposure and criticality are required", path))
	}
	return errors.Join(errs...)
}

// CatalogNames returns all catalog product names, sorted.
func (c *Config) CatalogNames() []string {
	names := make([]string, 0, len(c.Catalog))
	for n := range c.Catalog {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
