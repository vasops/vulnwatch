package config

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// HelmChart maps one Helm chart (by chart name) to the catalog products it
// deploys and where each product's version is read from.
type HelmChart map[string]VersionFrom

// Version sources inside a chart.
const (
	FromAppVersion   = "appVersion"   // Chart.yaml appVersion
	FromChartVersion = "chartVersion" // the chart version itself
	FromValues       = "values"       // an image tag in values.yaml
	FromSubchart     = "subchart"     // appVersion (or values) of a bundled dependency
)

// VersionFrom says where a product's version is read from. YAML forms:
//
//	appVersion | chartVersion
//	{values: prometheus.prometheusSpec.image.tag}
//	{subchart: grafana}                       (the subchart's appVersion)
//	{subchart: grafana, values: image.tag}    (a value inside the subchart)
type VersionFrom struct {
	Kind     string `yaml:"-"`
	Values   string `yaml:"values,omitempty"`
	Subchart string `yaml:"subchart,omitempty"`
}

func (v *VersionFrom) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != FromAppVersion && n.Value != FromChartVersion {
			return fmt.Errorf("line %d: want %s, %s or a mapping with values/subchart, got %q", n.Line, FromAppVersion, FromChartVersion, n.Value)
		}
		*v = VersionFrom{Kind: n.Value}
		return nil
	case yaml.MappingNode:
		var out VersionFrom
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			if val.Kind != yaml.ScalarNode || strings.TrimSpace(val.Value) == "" {
				return fmt.Errorf("line %d: %s must be a non-empty string", val.Line, k.Value)
			}
			switch k.Value {
			case FromValues:
				out.Values = val.Value
			case FromSubchart:
				out.Subchart = val.Value
			default:
				return fmt.Errorf("line %d: field %s not found in type config.VersionFrom", k.Line, k.Value)
			}
		}
		switch {
		case out.Subchart != "":
			out.Kind = FromSubchart
		case out.Values != "":
			out.Kind = FromValues
		default:
			return fmt.Errorf("line %d: want values and/or subchart", n.Line)
		}
		*v = out
		return nil
	}
	return fmt.Errorf("line %d: want %s, %s or a mapping", n.Line, FromAppVersion, FromChartVersion)
}

// MarshalYAML keeps the short forms for config dump.
func (v VersionFrom) MarshalYAML() (any, error) {
	switch v.Kind {
	case FromAppVersion, FromChartVersion:
		return v.Kind, nil
	}
	m := map[string]string{}
	if v.Subchart != "" {
		m[FromSubchart] = v.Subchart
	}
	if v.Values != "" {
		m[FromValues] = v.Values
	}
	return m, nil
}

func (v VersionFrom) String() string {
	switch v.Kind {
	case FromSubchart:
		if v.Values != "" {
			return "subchart " + v.Subchart + " values " + v.Values
		}
		return "subchart " + v.Subchart + " appVersion"
	case FromValues:
		return "values " + v.Values
	}
	return v.Kind
}

// HelmRelease is one deployed chart in stack.yaml. Products and versions
// come from the chart and the helm_charts mapping in the sources files.
type HelmRelease struct {
	Repo    string `yaml:"repo"`    // https://… chart repository or oci://registry/path
	Chart   string `yaml:"chart"`   // chart name
	Version string `yaml:"version"` // chart version
	// Versions overrides the version read from the chart for a product,
	// e.g. when your values pin a newer image than the chart default.
	Versions    map[string]string `yaml:"versions,omitempty"`
	Exposure    string            `yaml:"exposure,omitempty"`
	Criticality string            `yaml:"criticality,omitempty"`
	MinCVSS     *float64          `yaml:"min_cvss,omitempty"`
}

func (r HelmRelease) String() string { return r.Chart + " " + r.Version }

func (r HelmRelease) validate(path string) error {
	var errs []error
	if strings.TrimSpace(r.Repo) == "" || strings.TrimSpace(r.Chart) == "" || strings.TrimSpace(r.Version) == "" {
		errs = append(errs, fmt.Errorf("%s: repo, chart and version are required", path))
	}
	if r.Repo != "" && !strings.HasPrefix(r.Repo, "https://") && !strings.HasPrefix(r.Repo, "http://") && !strings.HasPrefix(r.Repo, "oci://") {
		errs = append(errs, fmt.Errorf("%s.repo: want https://… or oci://…, got %q", path, r.Repo))
	}
	for p, v := range r.Versions {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("%s.versions.%s: empty version", path, p))
		}
	}
	pd := ProductDefaults{MinCVSS: r.MinCVSS, Exposure: r.Exposure, Criticality: r.Criticality}
	if err := pd.validate(path, false); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// validateHelmCharts checks that every mapped product exists in the catalog.
func (c *Config) validateHelmCharts() error {
	var errs []error
	for _, chart := range SortedKeys(c.HelmCharts) {
		m := c.HelmCharts[chart]
		// An empty mapping ({}) is a known chart that deploys nothing worth
		// watching (CRDs, config objects): stack discover doesn't list it.
		for _, p := range SortedKeys(m) {
			if _, ok := c.Catalog[p]; !ok {
				errs = append(errs, fmt.Errorf("helm_charts.%s.%s: not a catalog product (use the catalog name, not an alias)", chart, p))
			}
		}
	}
	return errors.Join(errs...)
}

// HelmChartNames returns the mapped chart names, sorted.
func (c *Config) HelmChartNames() []string {
	return SortedKeys(c.HelmCharts)
}
