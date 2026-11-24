// Package config loads, merges and validates vulnwatch configuration.
//
// Nothing is built in. The config files (--app-config, see
// defaults/config.yaml) say how vulnwatch runs; the sources files (--sources,
// see defaults/sources.yaml) say where to look. Each kind may be layered:
// files are deep-merged in order (maps merge key by key, lists replace).
// stack.yaml declares what we run.
package config

// SchemaVersion is the only supported configuration schema version.
const SchemaVersion = 1

// Config is the merged effective configuration (defaults + user override).
type Config struct {
	Version         int                     `yaml:"version"`
	HTTP            HTTP                    `yaml:"http"`
	Run             Run                     `yaml:"run"`
	Sources         Sources                 `yaml:"sources"`
	Triage          Triage                  `yaml:"triage"`
	Outputs         Outputs                 `yaml:"outputs"`
	Metrics         Metrics                 `yaml:"metrics"`
	ProductDefaults ProductDefaults         `yaml:"product_defaults"`
	Catalog         map[string]CatalogEntry `yaml:"catalog"`
	// HelmCharts maps chart names to the catalog products they deploy.
	HelmCharts map[string]HelmChart `yaml:"helm_charts"`
	// IgnoreImages are images not worth a catalog entry (helper sidecars,
	// your own images, software without any advisory source), by group, so
	// overrides can add a group or drop one ([]). stack discover leaves them
	// out of its "not in the catalog" notes, Trivy out of unmatched images.
	IgnoreImages map[string][]string `yaml:"ignore_images"`
}

type HTTP struct {
	UserAgent        string   `yaml:"user_agent"`
	Timeout          Duration `yaml:"timeout"`
	Retries          int      `yaml:"retries"`
	RetryBackoff     Duration `yaml:"retry_backoff"`
	MaxConcurrency   int      `yaml:"max_concurrency"`
	MaxResponseBytes int64    `yaml:"max_response_bytes"`
}

type Run struct {
	Deadline         Duration `yaml:"deadline"`
	Overlap          Duration `yaml:"overlap"`
	RetryFailedAfter Duration `yaml:"retry_failed_after"` // 0: failed sources are not asked again
}

type Sources struct {
	GHSA     GHSASource     `yaml:"ghsa"`
	OSV      OSVSource      `yaml:"osv"`
	NVD      NVDSource      `yaml:"nvd"`
	CVEList  CVEListSource  `yaml:"cvelist"`
	RSS      RSSSource      `yaml:"rss"`
	K8sFeed  K8sFeedSource  `yaml:"kubernetes_cve_feed"`
	KEV      KEVSource      `yaml:"kev"`
	EPSS     EPSSSource     `yaml:"epss"`
	Exploits ExploitsSource `yaml:"exploits"`
	RedHat   RedHatSource   `yaml:"redhat"`
	Trivy    TrivySource    `yaml:"trivy"`
	OS       OSSource       `yaml:"os"`
	News     NewsSource     `yaml:"news"`
}

type GHSASource struct {
	Enabled    bool   `yaml:"enabled"`
	BaseURL    string `yaml:"base_url"`
	TokenEnv   string `yaml:"token_env"`
	APIVersion string `yaml:"api_version"`
	PerPage    int    `yaml:"per_page"`
	DetailURL  string `yaml:"detail_url"` // GitHub advisory page; {id} = GHSA ID
}

type OSVSource struct {
	Enabled bool   `yaml:"enabled"`
	BaseURL string `yaml:"base_url"`
}

type NVDSource struct {
	Enabled                bool     `yaml:"enabled"`
	BaseURL                string   `yaml:"base_url"`
	APIKeyEnv              string   `yaml:"api_key_env"`
	RequestInterval        Duration `yaml:"request_interval"`
	RequestIntervalWithKey Duration `yaml:"request_interval_with_key"`
	MaxWindow              Duration `yaml:"max_window"`
	ResultsPerPage         int      `yaml:"results_per_page"`
	DetailURL              string   `yaml:"detail_url"`
	MaxInFlight            int      `yaml:"max_in_flight"` // requests at once, retries included; 0: http.max_concurrency
	Timeout                Duration `yaml:"timeout"`       // per request; 0: http.timeout
	Budget                 Duration `yaml:"budget"`        // NVD time per run, from its first request; 0: no limit
}

// CVEListSource reads the CVE records as the CNAs publish them (the CVE
// Program's cvelistV5 repository, with CISA's Vulnrichment). Records are
// matched to products through an index in the state DB, built from the
// full dump (a release asset) on the first run and kept current with the
// daily and hourly delta releases. A product is matched by its catalog
// cvelist: names, nvd: CPEs and osv: package names.
type CVEListSource struct {
	Enabled     bool   `yaml:"enabled"`
	ReleasesURL string `yaml:"releases_url"` // GitHub releases API of the repository
	RecordsURL  string `yaml:"records_url"`  // single records: {records_url}/<year>/<n>xxx/<id>.json
	// WorkDir holds the downloaded archives during a run (about 1.3 GB on
	// the first one); it may be wiped between runs. Empty: $TMPDIR/vulnwatch-cvelist.
	WorkDir string `yaml:"work_dir"`
	// TokenEnv names an optional GitHub token, sent to api.github.com only
	// (listing releases; the archives themselves need none).
	TokenEnv string `yaml:"token_env"`
}

type RSSSource struct {
	Enabled bool `yaml:"enabled"`
}

// NewsSource lists the security news feeds `vulnwatch news` watches: a
// few, where the vulnerabilities the whole industry talks about show up
// before advisories name a product (Red Hat's security bulletins, CERT-EU's
// advisories). Each new item is posted once; it is not matched by version.
type NewsSource struct {
	Enabled bool       `yaml:"enabled"`
	Feeds   []NewsFeed `yaml:"feeds"`
}

// NewsFeed is one news feed.
type NewsFeed struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Format: rss (RSS or Atom) or rhsb (the list of Red Hat Security
	// Bulletins on access.redhat.com, which has no feed).
	Format string `yaml:"format"`
	// ExcludeTitle drops items whose title matches this regular expression
	// (e.g. CISA's daily "Adds … Known Exploited Vulnerabilities", which
	// the kev source covers).
	ExcludeTitle string `yaml:"exclude_title,omitempty"`
}

type K8sFeedSource struct {
	Enabled  bool     `yaml:"enabled"`
	URL      string   `yaml:"url"`
	Products []string `yaml:"products"`
}

type KEVSource struct {
	Enabled  bool     `yaml:"enabled"`
	URL      string   `yaml:"url"`
	CacheTTL Duration `yaml:"cache_ttl"`
}

// TrivySource reads trivy-operator's VulnerabilityReports from the cluster
// vulnwatch runs in (its service account; the Helm chart's trivy.enabled)
// and attaches them to products by the catalog's images. A finding only
// Trivy reports (no advisory for the product) is kept when a fixed package
// exists and it is KEV-listed, has EPSS >= MinEPSS, or reaches MinSeverity
// (MinSeverityInternet for internet-facing products).
type TrivySource struct {
	Enabled             bool    `yaml:"enabled"`
	MinSeverity         string  `yaml:"min_severity"`
	MinSeverityInternet string  `yaml:"min_severity_internet"`
	MinEPSS             float64 `yaml:"min_epss"`
}

// OSSource watches the nodes' kernel (stack.yaml os:) in the
// distribution's security tracker, queried through OSV (sources.osv.base_url).
// A kernel fix is only reported when it is KEV-listed or has EPSS >= MinEPSS:
// the tracker lists hundreds of kernel fixes per release.
type OSSource struct {
	Enabled bool    `yaml:"enabled"`
	MinEPSS float64 `yaml:"min_epss"`
}

// ExploitsSource flags findings with a public exploit: a Metasploit module
// or a Nuclei template naming the CVE. An empty URL turns that index off.
type ExploitsSource struct {
	Enabled       bool     `yaml:"enabled"`
	MetasploitURL string   `yaml:"metasploit_url"`
	NucleiURL     string   `yaml:"nuclei_url"`
	CacheTTL      Duration `yaml:"cache_ttl"`
}

type EPSSSource struct {
	Enabled   bool   `yaml:"enabled"`
	BaseURL   string `yaml:"base_url"`
	BatchSize int    `yaml:"batch_size"`
}

// RedHatSource adds Red Hat's rating and statement (when a flaw is
// exploitable) from the Red Hat Security Data API.
type RedHatSource struct {
	Enabled    bool   `yaml:"enabled"`
	BaseURL    string `yaml:"base_url"`
	BatchSize  int    `yaml:"batch_size"`  // CVEs per rating request
	MaxDetails int    `yaml:"max_details"` // statement requests per run, one per CVE
}

type Triage struct {
	Enabled     bool     `yaml:"enabled"`
	APIKeyEnv   string   `yaml:"api_key_env"`
	Model       string   `yaml:"model"`
	Effort      string   `yaml:"effort"` // low|medium|high|xhigh|max; empty: the model's default
	Language    string   `yaml:"language"`
	MaxFindings int      `yaml:"max_findings"`
	BatchSize   int      `yaml:"batch_size"`
	BaseURL     string   `yaml:"base_url"`
	MaxTokens   int      `yaml:"max_tokens"`
	Timeout     Duration `yaml:"timeout"`
}

// Metrics configures Prometheus metrics. vulnwatch runs as a batch job, so
// metrics are pushed to a Pushgateway at the end of each run.
type Metrics struct {
	PushgatewayURL string            `yaml:"pushgateway_url"` // empty: no push
	Job            string            `yaml:"job"`
	Grouping       map[string]string `yaml:"grouping,omitempty"` // extra grouping labels, e.g. {instance: prod}
	Timeout        Duration          `yaml:"timeout"`
}

type Outputs struct {
	Slack     SlackOutput     `yaml:"slack"`
	Webhook   WebhookOutput   `yaml:"webhook"`
	PagerDuty PagerDutyOutput `yaml:"pagerduty"`
	Teams     TeamsOutput     `yaml:"teams"`
}

// WebhookOutput POSTs one JSON run summary, and one JSON payload per P1
// finding, to a plain HTTP endpoint. Auth headers are never written to YAML:
// HeadersEnv names the header, the value comes from the named env var.
type WebhookOutput struct {
	URLEnv      string `yaml:"url_env"`
	AlertURLEnv string `yaml:"alert_url_env"` // falls back to the main URL
	// HeadersEnv maps a header name to the env var holding its value
	// (e.g. {Authorization: WEBHOOK_AUTH_HEADER}).
	HeadersEnv map[string]string `yaml:"headers_env,omitempty"`
	// DashboardURL is linked from the run summary; {from} and {to} become
	// now-30d and now.
	DashboardURL string `yaml:"dashboard_url"`
}

// PagerDutyOutput triggers one PagerDuty Events API v2 event per P1 finding,
// at the fixed enqueue endpoint (not configurable here): only the routing
// key is needed, and it's never written to YAML, only to the named env var.
type PagerDutyOutput struct {
	RoutingKeyEnv string `yaml:"routing_key_env"`
}

// TeamsOutput POSTs an Adaptive Card to a Teams Workflows webhook: one run
// summary to the main URL, one per P1 finding to the alert URL (falling
// back to the main URL, like WebhookOutput).
type TeamsOutput struct {
	URLEnv      string `yaml:"url_env"`
	AlertURLEnv string `yaml:"alert_url_env"` // falls back to the main URL
	// DashboardURL is linked from the run summary; {from} and {to} become
	// now-30d and now.
	DashboardURL string `yaml:"dashboard_url"`
}

type SlackOutput struct {
	BaseURL         string   `yaml:"base_url"`
	TokenEnv        string   `yaml:"token_env"`
	ChannelEnv      string   `yaml:"channel_env"`
	AlertChannelEnv string   `yaml:"alert_channel_env"`
	NewsChannelEnv  string   `yaml:"news_channel_env"` // vulnwatch news; unset: the channel_env channel
	MaxSectionText  int      `yaml:"max_section_text"`
	PostInterval    Duration `yaml:"post_interval"`
	// DashboardURL is linked from every message; {from} and {to} become
	// now-30d and now.
	DashboardURL string `yaml:"dashboard_url"`
}

// ProductDefaults are the per-product triage context defaults. Pointer
// fields distinguish "not set" from zero values while layering.
type ProductDefaults struct {
	MinCVSS     *float64 `yaml:"min_cvss,omitempty"`
	Exposure    string   `yaml:"exposure,omitempty"`
	Criticality string   `yaml:"criticality,omitempty"`
}

// CatalogEntry says where to look for one product.
type CatalogEntry struct {
	Enabled *bool        `yaml:"enabled,omitempty"`
	Aliases []string     `yaml:"aliases"`
	GHSA    []string     `yaml:"ghsa"`
	OSV     []OSVPackage `yaml:"osv"`
	NVD     []string     `yaml:"nvd"`
	// CVEList names the product as CVE records do (the CNA's affected
	// vendor and product); nvd: CPEs and osv: packages match there too.
	CVEList []CVEListName `yaml:"cvelist"`
	RSS     []string      `yaml:"rss"`
	// Images are container image repositories of the product (e.g.
	// quay.io/keycloak/keycloak); stack discover maps running images to
	// products with them. Mirrors and proxy caches match by path suffix.
	Images []string `yaml:"images,omitempty"`
}

// IsEnabled reports whether the entry is active (default true).
func (e CatalogEntry) IsEnabled() bool { return e.Enabled == nil || *e.Enabled }

type OSVPackage struct {
	Ecosystem string `yaml:"ecosystem"`
	Package   string `yaml:"package"`
}

// CVEListName is a vendor and product as a CVE record's affected list names
// them (e.g. "Apache Software Foundation", "Apache HTTP Server"), compared
// case-insensitively.
type CVEListName struct {
	Vendor  string `yaml:"vendor"`
	Product string `yaml:"product"`
}

// Allowed enum values.
var (
	Efforts       = []string{"low", "medium", "high", "xhigh", "max"}
	Exposures     = []string{"internet", "internal"}
	Criticalities = []string{"high", "medium", "low"}
	// TrivySeverities are the severities a Trivy filter accepts.
	TrivySeverities = []string{"medium", "high", "critical"}
	NewsFormats     = []string{"rss", "rhsb"}
)
