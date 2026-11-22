package catalog

import (
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/config"
)

func testConfig(t *testing.T, override string) *config.Config {
	t.Helper()
	srcs, err := config.ReadSources(false, "../../defaults/config.yaml", "../../defaults/sources.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Merge(append(srcs, config.Source{Name: "override", Data: []byte(override)})...)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestResolve(t *testing.T) {
	cfg := testConfig(t, "catalog: {myapp: {ghsa: [me/myapp]}, grafana: {enabled: false}}")
	stack, err := config.ParseStack([]byte(`
defaults: {exposure: internet}
products:
  k8s: "1.30.x"
  keycloak: {version: "26.x", criticality: high, min_cvss: 7}
  myapp: "*"
`))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := Resolve(cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Product{}
	for _, p := range ps {
		byName[p.Name] = p
	}
	k := byName["kubernetes"]
	if k.Name == "" || k.Exposure != "internet" || k.Criticality != "medium" || k.MinCVSS != 4.0 {
		t.Fatalf("kubernetes via alias: %+v", k)
	}
	kc := byName["keycloak"]
	if kc.Criticality != "high" || kc.MinCVSS != 7 || kc.Exposure != "internet" {
		t.Fatalf("keycloak layering: %+v", kc)
	}
	if m := byName["myapp"]; len(m.Entry.GHSA) != 1 || !m.Constraint.Any() {
		t.Fatalf("override-only product: %+v", m)
	}

	_, err = Resolve(cfg, &config.Stack{Products: map[string]config.ProductSpec{"grafana": {Version: "1"}}})
	if err == nil {
		t.Fatal("disabled product must not resolve")
	}
}

func TestResolveUnknownSuggests(t *testing.T) {
	cfg := testConfig(t, "")
	tests := []struct{ name, want string }{
		{"keycloack", "keycloak"},
		{"argo-cd2", "argocd"},
		{"gitlab-cee", "gitlab-ce"},
		{"prometheus-server", "prometheus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(cfg, &config.Stack{Products: map[string]config.ProductSpec{tt.name: {Version: "1"}}})
			if err == nil || !strings.Contains(err.Error(), "did you mean") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want suggestion %q, got %v", tt.want, err)
			}
		})
	}
	_, err := Resolve(cfg, &config.Stack{Products: map[string]config.ProductSpec{"zzzzzzzz": {Version: "1"}}})
	if err == nil || strings.Contains(err.Error(), "did you mean") {
		t.Fatalf("no suggestion expected: %v", err)
	}
}

func TestResolveBadConstraint(t *testing.T) {
	cfg := testConfig(t, "")
	_, err := Resolve(cfg, &config.Stack{Products: map[string]config.ProductSpec{"keycloak": {Version: ">=27 <26"}}})
	if err == nil || !strings.Contains(err.Error(), "matches no version") {
		t.Fatalf("got %v", err)
	}
}

func TestResolveMergesExtras(t *testing.T) {
	cfg := testConfig(t, "catalog: {mariadb: {enabled: false}}")
	stack, err := config.ParseStack([]byte("products:\n  keycloak: {version: '26.7.0', exposure: internet}\n"))
	if err != nil {
		t.Fatal(err)
	}
	high, low := 7.0, 2.0
	ps, err := Resolve(cfg, stack,
		Extra{Product: "keycloak", Version: "20.0.3", From: "keycloak 13.0.5 (appVersion)",
			ProductDefaults: config.ProductDefaults{Exposure: "internal", Criticality: "high", MinCVSS: &low}},
		Extra{Product: "grafana", Version: "13.0.5", From: "a", ProductDefaults: config.ProductDefaults{MinCVSS: &high}},
		Extra{Product: "grafana", Version: "13.2.4", From: "b"},
		Extra{Product: "grafana", Version: "13.0.5", From: "c"},
		Extra{Product: "mariadb", Version: "11.4", From: "disabled in catalog"},
	)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Product{}
	for _, p := range ps {
		by[p.Name] = p
	}
	kc := by["keycloak"]
	if kc.Constraint.String() != "26.7.0 || 20.0.3" || kc.Exposure != "internet" || kc.Criticality != "high" || kc.MinCVSS != 2 ||
		strings.Join(kc.Origins, ";") != "stack.yaml;keycloak 13.0.5 (appVersion)" {
		t.Fatalf("keycloak merge: %+v", kc)
	}
	if g := by["grafana"]; g.Constraint.String() != "13.0.5 || 13.2.4" || g.MinCVSS != 7 || g.Exposure != "internal" {
		t.Fatalf("grafana merge: %+v", g)
	}
	if _, ok := by["mariadb"]; ok || len(ps) != 2 {
		t.Fatalf("disabled products are skipped: %+v", ps)
	}
}

func TestKernelProduct(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"debian", "13"}:          "debian-13-kernel",
		{"rhel", "9.4"}:           "rhel-9.4-kernel",
		{"sles", "15 SP6"}:        "sles-15-sp6-kernel",
		{"sles", "15-SP6"}:        "sles-15-sp6-kernel",
		{"ubuntu", "24.04"}:       "ubuntu-24.04-kernel",
		{"opensuse-leap", "15.6"}: "opensuse-leap-15.6-kernel",
	} {
		if got := KernelProduct(&config.StackOS{Name: in[0], Release: in[1]}); got != want {
			t.Errorf("%v = %q, want %q", in, got, want)
		}
	}
}
