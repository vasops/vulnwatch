package config

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Stack is stack.yaml: what we run. The top level is the local stack, the
// cluster vulnwatch runs in (the only one Trivy and node discovery see);
// tenants are other stacks watched from here, per environment.
type Stack struct {
	Version int `yaml:"version,omitempty"`
	// Tenant and Environment name the local stack in reports, metrics and
	// dashboards (default "local" and "default").
	Tenant      string                 `yaml:"tenant,omitempty"`
	Environment string                 `yaml:"environment,omitempty"`
	GeneratedAt Date                   `yaml:"generated_at,omitempty"` // the local stack's, see EnvironmentSpec
	Defaults    ProductDefaults        `yaml:"defaults,omitempty"`     // for every tenant
	Products    map[string]ProductSpec `yaml:"products"`
	// Helm lists deployed charts; their products and versions are read
	// from the charts (see helm_charts in the sources files).
	Helm []HelmRelease `yaml:"helm,omitempty"`
	// OS is the nodes' operating system; its running kernel is watched as
	// the product <name>-<release>-kernel, e.g. debian-13-kernel.
	OS *StackOS `yaml:"os,omitempty"`
	// Tenants are customers, organizations or teams whose stacks are
	// watched from here, by name.
	Tenants map[string]TenantSpec `yaml:"tenants,omitempty"`
}

// TenantSpec is one tenant: settings for all its environments, and the
// environments' stacks by name.
type TenantSpec struct {
	Defaults     ProductDefaults            `yaml:"defaults,omitempty"`
	Slack        SlackRoute                 `yaml:"slack,omitempty"`
	Environments map[string]EnvironmentSpec `yaml:"environments"`
}

// EnvironmentSpec is one environment's stack (prod, stage, a cluster).
type EnvironmentSpec struct {
	// GeneratedAt is when stack discover or merge last read the stack from
	// its cluster: how old the inventory is.
	GeneratedAt Date                   `yaml:"generated_at,omitempty"`
	Defaults    ProductDefaults        `yaml:"defaults,omitempty"`
	Slack       SlackRoute             `yaml:"slack,omitempty"`
	Products    map[string]ProductSpec `yaml:"products,omitempty"`
	Helm        []HelmRelease          `yaml:"helm,omitempty"`
	OS          *StackOS               `yaml:"os,omitempty"`
}

// SlackRoute sends a tenant's (or environment's) Slack messages to its own
// channels (IDs). Without a channel they go to the default ones.
type SlackRoute struct {
	Channel      string `yaml:"channel,omitempty"`       // run summary
	AlertChannel string `yaml:"alert_channel,omitempty"` // P1 alerts; default: channel
}

// Names of the local stack when stack.yaml doesn't set them.
const (
	DefaultTenant      = "local"
	DefaultEnvironment = "default"
)

// Scope is where a product runs: a tenant's environment, or the local stack.
type Scope struct {
	Tenant      string
	Environment string
	Remote      bool       // a tenant's environment; false: the local stack, the cluster vulnwatch runs in
	Slack       SlackRoute // the environment's route, else the tenant's
	GeneratedAt time.Time  // the stack's generated_at (00:00 UTC); zero if it has none
}

// Date is a calendar day written as YYYY-MM-DD, held as 00:00 UTC.
type Date struct{ time.Time }

func (d *Date) UnmarshalYAML(n *yaml.Node) error {
	t, err := time.Parse(time.DateOnly, n.Value)
	if n.Kind != yaml.ScalarNode || err != nil {
		return fmt.Errorf("line %d: want a date like 2026-11-13, got %q", n.Line, n.Value)
	}
	d.Time = t
	return nil
}

// Prefix is put before the product name in state keys: empty for the
// local stack, so state written before tenants existed stays valid.
func (s Scope) Prefix() string {
	if !s.Remote {
		return ""
	}
	return s.Tenant + "/" + s.Environment + "/"
}

// String is "tenant/environment".
func (s Scope) String() string { return s.Tenant + "/" + s.Environment }

// ScopedStack is the stack of one scope, its defaults layered (stack.yaml
// defaults, then the tenant's, then the environment's).
type ScopedStack struct {
	Scope Scope
	Path  string // in stack.yaml, for messages: "" or "tenants.acme.environments.prod"
	Stack *Stack
}

// Scopes returns the local stack (when it lists anything), then every
// tenant environment, sorted.
func (s *Stack) Scopes() []ScopedStack {
	var out []ScopedStack
	if len(s.Products) > 0 || len(s.Helm) > 0 || s.OS != nil {
		out = append(out, ScopedStack{
			Scope: Scope{Tenant: cmp.Or(s.Tenant, DefaultTenant), Environment: cmp.Or(s.Environment, DefaultEnvironment), GeneratedAt: s.GeneratedAt.Time},
			Stack: &Stack{Defaults: s.Defaults, Products: s.Products, Helm: s.Helm, OS: s.OS},
		})
	}
	for _, tn := range SortedKeys(s.Tenants) {
		t := s.Tenants[tn]
		for _, en := range SortedKeys(t.Environments) {
			e := t.Environments[en]
			out = append(out, ScopedStack{
				Scope: Scope{Tenant: tn, Environment: en, Remote: true, Slack: SlackRoute{
					Channel:      cmp.Or(e.Slack.Channel, t.Slack.Channel),
					AlertChannel: cmp.Or(e.Slack.AlertChannel, t.Slack.AlertChannel),
				}, GeneratedAt: e.GeneratedAt.Time},
				Path: "tenants." + tn + ".environments." + en,
				Stack: &Stack{
					Defaults: LayerDefaults(LayerDefaults(s.Defaults, t.Defaults), e.Defaults),
					Products: e.Products, Helm: e.Helm, OS: e.OS,
				},
			})
		}
	}
	return out
}

// MultiTenant reports whether stack.yaml has tenants.
func (s *Stack) MultiTenant() bool { return len(s.Tenants) > 0 }

// LayerDefaults returns base with the settings over sets replacing it.
func LayerDefaults(base, over ProductDefaults) ProductDefaults {
	if over.MinCVSS != nil {
		base.MinCVSS = over.MinCVSS
	}
	if over.Exposure != "" {
		base.Exposure = over.Exposure
	}
	if over.Criticality != "" {
		base.Criticality = over.Criticality
	}
	return base
}

// scopeNameRe is what tenant and environment names may look like: they
// become state keys, metric labels and dashboard variables.
var scopeNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// OS distributions whose kernel security data OSV has.
var OSNames = []string{"debian", "ubuntu", "rhel", "rocky", "almalinux", "sles", "opensuse-leap"}

// StackOS is the nodes' operating system release and running kernel(s).
type StackOS struct {
	Name    string `yaml:"name"`    // see OSNames
	Release string `yaml:"release"` // e.g. "13", "24.04", "9.4", "15 SP6"
	// Kernel is the running kernel package version(s), e.g.
	// "6.12.48 || 6.12.62" (Debian 13: uname -r up to "+"), "6.8.0-71"
	// (Ubuntu), "5.14.0-427.13.1.el9_4" (RHEL, Rocky, AlmaLinux: uname -r
	// without the architecture), "6.4.0-150600.23.17.1" (SUSE).
	Kernel string `yaml:"kernel"`
	// KernelPackage overrides the kernel package: linux (Debian, Ubuntu),
	// kernel (RHEL family), kernel-default (SUSE); e.g. linux-aws or
	// kernel-azure for cloud kernels.
	KernelPackage string   `yaml:"kernel_package,omitempty"`
	Exposure      string   `yaml:"exposure,omitempty"`
	Criticality   string   `yaml:"criticality,omitempty"`
	MinCVSS       *float64 `yaml:"min_cvss,omitempty"`
}

func (o *StackOS) validate(prefix string) error {
	var errs []error
	if !slices.Contains(OSNames, o.Name) {
		errs = append(errs, fmt.Errorf("%sos.name: want one of %v, got %q", prefix, OSNames, o.Name))
	}
	if strings.TrimSpace(o.Release) == "" || strings.TrimSpace(o.Kernel) == "" {
		errs = append(errs, fmt.Errorf("%sos: release and kernel are required", prefix))
	}
	pd := ProductDefaults{MinCVSS: o.MinCVSS, Exposure: o.Exposure, Criticality: o.Criticality}
	if err := pd.validate(prefix+"os", false); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ProductSpec is one product entry; either a bare version constraint
// ("26.x") or the long form with triage context.
type ProductSpec struct {
	Version     string   `yaml:"version"`
	Exposure    string   `yaml:"exposure,omitempty"`
	Criticality string   `yaml:"criticality,omitempty"`
	MinCVSS     *float64 `yaml:"min_cvss,omitempty"`
}

func (p *ProductSpec) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		p.Version = n.Value
		return nil
	case yaml.MappingNode:
		type plain ProductSpec
		var v plain
		// Re-encode so KnownFields applies to the nested mapping too.
		b, err := yaml.Marshal(n)
		if err != nil {
			return err
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("line %d: %w", n.Line, err)
		}
		*p = ProductSpec(v)
		return nil
	default:
		return fmt.Errorf("line %d: product must be a version string or a mapping", n.Line)
	}
}

// LoadStack reads and strictly decodes stack.yaml.
func LoadStack(path string) (*Stack, error) {
	b, err := os.ReadFile(path) //nolint:gosec // reading the file the operator names is the point
	if err != nil {
		return nil, fmt.Errorf("read stack config: %w", err)
	}
	return ParseStack(b)
}

// ParseStack strictly decodes stack.yaml content and checks its shape.
func ParseStack(b []byte) (*Stack, error) {
	var s Stack
	if err := strictDecode(b, &s); err != nil {
		return nil, fmt.Errorf("stack config: %w", err)
	}
	if s.Version != 0 && s.Version != SchemaVersion {
		return nil, fmt.Errorf("stack config: unsupported version %d (want %d)", s.Version, SchemaVersion)
	}
	var errs []error
	if len(s.Products) == 0 && len(s.Helm) == 0 && s.OS == nil && len(s.Tenants) == 0 {
		errs = append(errs, errors.New("stack config: products, helm, os and tenants must not all be empty"))
	}
	local := Scope{Tenant: cmp.Or(s.Tenant, DefaultTenant), Environment: cmp.Or(s.Environment, DefaultEnvironment)}
	for _, n := range []struct{ path, name string }{{"tenant", local.Tenant}, {"environment", local.Environment}} {
		if !scopeNameRe.MatchString(n.name) {
			errs = append(errs, fmt.Errorf("stack config: %s: %q: want lowercase letters, digits, '.', '_' or '-'", n.path, n.name))
		}
	}
	if err := s.Defaults.validate("stack config: defaults", false); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, validateBody("stack config: ", s.Products, s.Helm, s.OS)...)
	for _, tn := range SortedKeys(s.Tenants) {
		t := s.Tenants[tn]
		tp := "stack config: tenants." + tn
		if !scopeNameRe.MatchString(tn) {
			errs = append(errs, fmt.Errorf("%s: want lowercase letters, digits, '.', '_' or '-' in the name", tp))
		}
		if len(t.Environments) == 0 {
			errs = append(errs, fmt.Errorf("%s: environments: at least one is required", tp))
		}
		if err := t.Defaults.validate(tp+".defaults", false); err != nil {
			errs = append(errs, err)
		}
		for _, en := range SortedKeys(t.Environments) {
			e := t.Environments[en]
			ep := tp + ".environments." + en
			if !scopeNameRe.MatchString(en) {
				errs = append(errs, fmt.Errorf("%s: want lowercase letters, digits, '.', '_' or '-' in the name", ep))
			}
			if tn == local.Tenant && en == local.Environment {
				errs = append(errs, fmt.Errorf("%s: is the local stack's name (top-level tenant and environment); rename one", ep))
			}
			if len(e.Products) == 0 && len(e.Helm) == 0 && e.OS == nil {
				errs = append(errs, fmt.Errorf("%s: products, helm and os must not all be empty", ep))
			}
			if err := e.Defaults.validate(ep+".defaults", false); err != nil {
				errs = append(errs, err)
			}
			errs = append(errs, validateBody(ep+".", e.Products, e.Helm, e.OS)...)
		}
	}
	return &s, errors.Join(errs...)
}

// validateBody checks the products, helm and os of one stack; prefix is
// "stack config: " or "stack config: tenants.<t>.environments.<e>.".
func validateBody(prefix string, products map[string]ProductSpec, helm []HelmRelease, o *StackOS) []error {
	var errs []error
	if o != nil {
		if err := o.validate(prefix); err != nil {
			errs = append(errs, err)
		}
	}
	for i, r := range helm {
		if err := r.validate(fmt.Sprintf("%shelm[%d]", prefix, i)); err != nil {
			errs = append(errs, err)
		}
	}
	for _, name := range SortedKeys(products) {
		p := products[name]
		path := prefix + "products." + name
		if strings.TrimSpace(p.Version) == "" {
			errs = append(errs, fmt.Errorf("%s: version is required", path))
		}
		pd := ProductDefaults{MinCVSS: p.MinCVSS, Exposure: p.Exposure, Criticality: p.Criticality}
		if err := pd.validate(path, false); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
