package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	exampleConfigFile = "../../defaults/config.yaml"
	exampleSources    = "../../defaults/sources.yaml"
)

func exampleConfig(t *testing.T, extra ...Source) *Config {
	t.Helper()
	srcs, err := ReadSources(false, exampleConfigFile, exampleSources)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(append(srcs, extra...)...)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestExampleSourcesValid(t *testing.T) {
	cfg := exampleConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Catalog) == 0 {
		t.Fatal("empty catalog")
	}
}

func TestMerge(t *testing.T) {
	base := []byte(`
version: 1
http: {user_agent: ua, timeout: 30s, retries: 3, retry_backoff: 2s, max_concurrency: 8}
run: {deadline: 20m, overlap: 24h}
sources:
  osv: {enabled: true, base_url: osv.example}
  nvd: {enabled: true, base_url: nvd.example, max_window: 120d, request_interval: 6s}
product_defaults: {min_cvss: 4.0, exposure: internal, criticality: medium}
catalog:
  alpha:
    aliases: [a]
    ghsa: [org/alpha]
    nvd: ["cpe:2.3:a:org:alpha"]
  beta:
    ghsa: [org/beta]
`)
	tests := []struct {
		name     string
		override string
		check    func(t *testing.T, c *Config)
		wantErr  string
	}{
		{
			name:     "no override",
			override: "",
			check: func(t *testing.T, c *Config) {
				if c.Sources.OSV.BaseURL != "osv.example" || len(c.Catalog) != 2 {
					t.Fatalf("unexpected: %+v", c)
				}
			},
		},
		{
			name:     "scalar override, sibling keys kept",
			override: "http: {timeout: 5s}",
			check: func(t *testing.T, c *Config) {
				if c.HTTP.Timeout.D().Seconds() != 5 || c.HTTP.UserAgent != "ua" || c.HTTP.Retries != 3 {
					t.Fatalf("map merge broken: %+v", c.HTTP)
				}
			},
		},
		{
			name:     "lists replace",
			override: "catalog: {alpha: {ghsa: [other/repo]}}",
			check: func(t *testing.T, c *Config) {
				a := c.Catalog["alpha"]
				if len(a.GHSA) != 1 || a.GHSA[0] != "other/repo" {
					t.Fatalf("list not replaced: %v", a.GHSA)
				}
				if len(a.NVD) != 1 || len(a.Aliases) != 1 {
					t.Fatalf("sibling lists lost: %+v", a)
				}
			},
		},
		{
			name:     "empty list clears",
			override: "catalog: {alpha: {nvd: []}}",
			check: func(t *testing.T, c *Config) {
				if len(c.Catalog["alpha"].NVD) != 0 {
					t.Fatalf("not cleared: %v", c.Catalog["alpha"].NVD)
				}
			},
		},
		{
			name:     "disable product and source",
			override: "catalog: {beta: {enabled: false}}\nsources: {nvd: {enabled: false}}",
			check: func(t *testing.T, c *Config) {
				if c.Catalog["beta"].IsEnabled() {
					t.Fatal("beta still enabled")
				}
				if c.Sources.NVD.Enabled || c.Sources.NVD.BaseURL != "nvd.example" {
					t.Fatalf("nvd: %+v", c.Sources.NVD)
				}
			},
		},
		{
			name:     "add product",
			override: "catalog: {gamma: {osv: [{ecosystem: PyPI, package: gamma}]}}",
			check: func(t *testing.T, c *Config) {
				g, ok := c.Catalog["gamma"]
				if !ok || len(g.OSV) != 1 || !g.IsEnabled() {
					t.Fatalf("gamma: %+v", g)
				}
			},
		},
		{
			name:     "unknown key rejected",
			override: "sources: {osv: {base_ulr: typo}}",
			wantErr:  "base_ulr",
		},
		{
			name:     "unknown top-level key rejected",
			override: "sourcez: {}",
			wantErr:  "sourcez",
		},
		{
			name:     "wrong version rejected",
			override: "version: 2",
			wantErr:  "unsupported version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Merge(Source{"base", base}, Source{"override", []byte(tt.override)})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(ov, []byte("triage: {model: from-file, language: de}"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{EnvClaudeModel: "from-env", EnvMaxLLMFindings: "7"}
	getenv := func(k string) string { return env[k] }
	cfg, err := Load(LoadOptions{ConfigPaths: []string{exampleConfigFile, ov}, Paths: []string{exampleSources}, Getenv: getenv})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Triage.Model != "from-env" || cfg.Triage.Language != "de" || cfg.Triage.MaxFindings != 7 {
		t.Fatalf("precedence broken: %+v", cfg.Triage)
	}
	env[EnvMaxLLMFindings] = "lots"
	if _, err := Load(LoadOptions{ConfigPaths: []string{exampleConfigFile}, Paths: []string{exampleSources}, Getenv: getenv}); err == nil {
		t.Fatal("want error for invalid MAX_LLM_FINDINGS")
	}
	if _, err := Load(LoadOptions{Paths: []string{exampleSources}}); err == nil || !strings.Contains(err.Error(), "no config file") {
		t.Fatalf("want missing config error, got %v", err)
	}
	if _, err := Load(LoadOptions{ConfigPaths: []string{exampleConfigFile}}); err == nil || !strings.Contains(err.Error(), "no sources file") {
		t.Fatalf("want missing sources error, got %v", err)
	}
	if _, err := Load(LoadOptions{ConfigPaths: []string{exampleConfigFile}, Paths: []string{filepath.Join(dir, "missing.yaml")}}); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestLoadRejectsMixedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	srcWithTriage := write("s.yaml", "triage: {language: de}\ncatalog: {}\n")
	cfgWithCatalog := write("c.yaml", "catalog: {x: {ghsa: [a/b]}}\nhelm_charts: {}\n")
	typo := write("t.yaml", "htpp: {}\n")
	tests := []struct {
		cfgs, srcs []string
		want       []string
	}{
		{[]string{exampleConfigFile}, []string{exampleSources, srcWithTriage}, []string{`"triage" belongs in the config file`}},
		{[]string{exampleConfigFile, cfgWithCatalog}, []string{exampleSources}, []string{`"catalog" belongs in the sources file`, `"helm_charts" belongs in the sources file`}},
		{[]string{typo}, []string{exampleSources}, []string{`unknown top-level key "htpp"`}},
	}
	for _, tt := range tests {
		_, err := Load(LoadOptions{ConfigPaths: tt.cfgs, Paths: tt.srcs, Getenv: func(string) string { return "" }})
		for _, w := range tt.want {
			if err == nil || !strings.Contains(err.Error(), w) {
				t.Errorf("want %q, got %v", w, err)
			}
		}
	}
}

func TestValidateCatalog(t *testing.T) {
	cfg := exampleConfig(t, Source{"override", []byte(`
catalog:
  dup: {aliases: [k8s]}
  bad: {nvd: ["kubernetes"], ghsa: [norepo], osv: [{ecosystem: Go}], cvelist: [{vendor: Apache Software Foundation}]}
  httpd: {cvelist: [{vendor: Apache Software Foundation, product: Apache HTTP Server}]}
`)})
	if got := cfg.Catalog["httpd"].CVEList; len(got) != 1 || got[0].Product != "Apache HTTP Server" {
		t.Fatalf("cvelist names: %+v", got)
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("want validation errors")
	}
	for _, want := range []string{`alias "k8s" already used`, "not a CPE", "not owner/repo", "ecosystem and package", "bad.cvelist[0]: vendor and product"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
}

func TestParseStack(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string
	}{
		{"short and long form", "products:\n  longhorn: \"1.8.1\"\n  keycloak: {version: 26.x, exposure: internet}\n", ""},
		{"unquoted number", "products:\n  longhorn: 1.8\n", ""},
		{"missing version", "products:\n  keycloak: {exposure: internet}\n", "version is required"},
		{"bad enum", "products:\n  keycloak: {version: '1', exposure: dmz}\n", "exposure"},
		{"unknown product key", "products:\n  keycloak: {version: '1', exposures: internet}\n", "exposures"},
		{"unknown top key", "product: {}\n", "product"},
		{"empty", "products: {}\n", "must not all be empty"},
		{"bad defaults", "defaults: {min_cvss: 11}\nproducts: {a: '1'}\n", "min_cvss"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseStack([]byte(tt.in))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestDumpRedactsSecrets(t *testing.T) {
	cfg := exampleConfig(t)
	out, err := cfg.Dump(func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "ghp_supersecret"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supersecret") {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(string(out), "GITHUB_TOKEN: set (redacted)") {
		t.Fatalf("missing secret status:\n%s", out)
	}
}

// A webhook auth header's env var (e.g. an Authorization bearer token) must
// show up in the secrets section too, set/unset only, like every other
// *TokenEnv: config dump should say whether it's configured without ever
// printing its value.
func TestDumpReportsWebhookHeaderEnvStatus(t *testing.T) {
	cfg := exampleConfig(t)
	cfg.Outputs.Webhook.HeadersEnv = map[string]string{"Authorization": "WEBHOOK_AUTH_HEADER"}
	out, err := cfg.Dump(func(k string) string {
		if k == "WEBHOOK_AUTH_HEADER" {
			return "Bearer supersecret"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supersecret") {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(string(out), "WEBHOOK_AUTH_HEADER: set (redacted)") {
		t.Fatalf("missing secret status:\n%s", out)
	}
}

func TestMergeOrderAndOrigins(t *testing.T) {
	a := Source{"a.yaml", []byte("catalog: {x: {ghsa: [o/a]}, y: {ghsa: [o/y]}}")}
	b := Source{"b.yaml", []byte("catalog: {x: {ghsa: [o/b]}}")}
	c := Source{"c.yaml", []byte("catalog: {x: {aliases: [ex]}}")}
	cfg, err := Merge(a, b, c)
	if err != nil {
		t.Fatal(err)
	}
	if x := cfg.Catalog["x"]; x.GHSA[0] != "o/b" || x.Aliases[0] != "ex" {
		t.Fatalf("later files must win key by key: %+v", x)
	}
	o := CatalogOrigins(a, b, c)
	if strings.Join(o["x"], ",") != "a.yaml,b.yaml,c.yaml" || strings.Join(o["y"], ",") != "a.yaml" {
		t.Fatalf("origins: %v", o)
	}
}

func TestHelmChartsConfig(t *testing.T) {
	cfg := exampleConfig(t, Source{"override", []byte(`
helm_charts:
  mystack:
    prometheus: appVersion
    grafana: {subchart: grafana}
    alertmanager: {values: a.b.tag}
    loki: {subchart: loki, values: image.tag}
    vault: chartVersion
`)})
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	m := cfg.HelmCharts["mystack"]
	if m["prometheus"].Kind != FromAppVersion || m["vault"].Kind != FromChartVersion ||
		m["grafana"].Kind != FromSubchart || m["alertmanager"] != (VersionFrom{Kind: FromValues, Values: "a.b.tag"}) ||
		m["loki"] != (VersionFrom{Kind: FromSubchart, Subchart: "loki", Values: "image.tag"}) {
		t.Fatalf("decoded: %+v", m)
	}
	if len(exampleConfig(t).HelmCharts) == 0 {
		t.Fatal("example sources must map the example charts")
	}
	for _, tt := range []struct{ in, want string }{
		{"helm_charts: {x: {prometheus: latest}}", `got "latest"`},
		{"helm_charts: {x: {prometheus: {valuez: a}}}", "valuez"},
		{"helm_charts: {x: {prometheus: {}}}", "want values and/or subchart"},
	} {
		if _, err := Merge(Source{"o", []byte(tt.in)}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: want %q, got %v", tt.in, tt.want, err)
		}
	}
	bad := exampleConfig(t, Source{"o", []byte("helm_charts: {x: {k8s: appVersion}}")})
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "not a catalog product") {
		t.Fatalf("alias instead of catalog name must fail: %v", err)
	}
}

func TestParseStackHelm(t *testing.T) {
	s, err := ParseStack([]byte(`
helm:
  - {repo: oci://ghcr.io/x, chart: a, version: 1.0.0, exposure: internet, versions: {minio: RELEASE.2025-04-22T22-12-26Z}}
`))
	if err != nil || len(s.Helm) != 1 || s.Helm[0].Versions["minio"] == "" || s.Helm[0].Exposure != "internet" {
		t.Fatalf("helm-only stack: %+v %v", s, err)
	}
	for _, tt := range []struct{ in, want string }{
		{"helm: [{repo: https://x, chart: a}]", "repo, chart and version are required"},
		{"helm: [{repo: ftp://x, chart: a, version: '1'}]", "want https://"},
		{"helm: [{repo: https://x, chart: a, version: '1', exposure: dmz}]", "exposure"},
		{"helm: [{repo: https://x, chart: a, version: '1', chartz: b}]", "chartz"},
	} {
		if _, err := ParseStack([]byte(tt.in)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: want %q, got %v", tt.in, tt.want, err)
		}
	}
}

// TestExampleStack checks examples/stack.yaml offline: it parses, its
// products exist, and every chart it lists has a helm_charts mapping.
func TestExampleStack(t *testing.T) {
	cfg := exampleConfig(t)
	s, err := LoadStack("../../examples/stack.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Helm) == 0 || len(s.Products) == 0 {
		t.Fatalf("example stack should show both forms: %+v", s)
	}
	for name := range s.Products {
		if _, ok := cfg.Catalog[name]; !ok {
			t.Errorf("products.%s: not a catalog product", name)
		}
	}
	for _, r := range s.Helm {
		if _, ok := cfg.HelmCharts[r.Chart]; !ok {
			t.Errorf("helm chart %s: no helm_charts mapping in defaults/sources.yaml", r.Chart)
		}
	}
}

func TestTriageEffort(t *testing.T) {
	cfg := exampleConfig(t)
	if cfg.Triage.Model != "claude-haiku-5-5" || cfg.Triage.Effort != "high" {
		t.Fatalf("example defaults: model %q effort %q", cfg.Triage.Model, cfg.Triage.Effort)
	}
	env := map[string]string{EnvClaudeEffort: "max"}
	loaded, err := Load(LoadOptions{ConfigPaths: []string{exampleConfigFile}, Paths: []string{exampleSources}, Getenv: func(k string) string { return env[k] }})
	if err != nil || loaded.Triage.Effort != "max" {
		t.Fatalf("env override: %v %+v", err, loaded)
	}
	bad := exampleConfig(t, Source{"o", []byte("triage: {enabled: true, effort: extreme}")})
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), `triage.effort: "extreme"`) {
		t.Fatalf("want effort validation error, got %v", err)
	}
	empty := exampleConfig(t, Source{"o", []byte("triage: {enabled: true, effort: ''}")})
	if err := empty.Validate(); err != nil {
		t.Fatalf("empty effort means the model default: %v", err)
	}
}

func TestNewsFeeds(t *testing.T) {
	cfg := exampleConfig(t)
	if !cfg.Sources.News.Enabled || len(cfg.Sources.News.Feeds) == 0 {
		t.Fatalf("example news: %+v", cfg.Sources.News)
	}
	bad := exampleConfig(t, Source{"o", []byte(`sources:
  news:
    feeds:
      - {name: a, url: 'ftp://x', format: atom}
      - {name: a, url: 'https://x', format: rss, exclude_title: '('}
`)})
	err := bad.Validate()
	for _, want := range []string{"feeds[0].url", "feeds[0].format", `feeds[1].name: "a" is used twice`, "feeds[1].exclude_title"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q in %v", want, err)
		}
	}
}
