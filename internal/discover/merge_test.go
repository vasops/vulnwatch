package discover

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/match"
)

const valuesFile = `# vulnwatch values
stack:
  defaults:
    exposure: internal     # internet | internal

  helm:
    - { repo: https://argoproj.github.io/argo-helm, chart: argo-cd, version: 10.9.2 }
    - { repo: https://grafana.github.io/helm-charts, chart: loki, version: 7.2.0 }        # loki and loki-fleet
    - { repo: https://helm.goharbor.io, chart: harbor, version: 1.16.2 }
    - { repo: https://helm.goharbor.io, chart: harbor, version: 1.18.4 }
    - repo: https://charts.min.io/
      chart: minio
      version: 5.4.0
      versions:
        minio: RELEASE.2025-01-01T00-00-00Z   # pinned

  products:
    k8s: ">=1.33.0"                      # every cluster
    cilium: "1.18.2"
    postgresql: "17.4"
    grafana: "13.0.5 || 13.2.4"

    keycloak:
      version: "26.7.0"
      criticality: high
    gitlab-ce:
      version: "19.5.3"
      exposure: internal

resources: {}
`

const valuesMerged = `# vulnwatch values
stack:
  defaults:
    exposure: internal     # internet | internal

  helm:
    - { repo: https://argoproj.github.io/argo-helm, chart: argo-cd, version: 10.9.7, exposure: internet }
    - { repo: https://grafana.github.io/helm-charts, chart: loki, version: 7.2.0, versions: { loki: "3.6.9" } }        # loki and loki-fleet
    - { repo: https://helm.goharbor.io, chart: harbor, version: 1.16.2 }
    - { repo: https://helm.goharbor.io, chart: harbor, version: 1.18.4 }
    - repo: https://charts.min.io/
      chart: minio
      version: 5.4.0
      versions:
        minio: RELEASE.2025-04-22T22-12-26Z   # pinned
        minio-mc: "RELEASE.2025-04-01T00-00-00Z"
      exposure: internet
    - { repo: https://helm.goharbor.io, chart: harbor, version: 1.20.0 }  # argocd app harbor
    - repo: https://charts.jetstack.io  # argocd app cert-manager
      chart: cert-manager
      version: v1.20.6
      exposure: internet  # HTTPRoute certs.example.com

  products:
    k8s: ">=1.33.0"                      # every cluster
    cilium: "1.18.3"
    postgresql: { version: "17.4", exposure: internet }
    grafana: "13.0.5 || 13.2.4 || 13.3.2"

    keycloak:
      version: "26.7.0"
      criticality: high
      exposure: internet
    gitlab-ce:
      version: "19.5.3"
      exposure: internal
    containerd: "2.2.3"  # container runtime on the nodes
  generated_at: "2026-11-13"  # inventory date; stack merge updates it

resources: {}
`

// day is when the tests merge: generated_at is its date (UTC).
var day = time.Date(2026, 11, 14, 0, 30, 0, 0, time.FixedZone("CET", 3600))

func declaredOf(t *testing.T, cfg *config.Config, src string, key string) map[string]match.Constraint {
	t.Helper()
	stack, err := config.ParseStack([]byte(src))
	if key != "" {
		var wrapped struct {
			Stack config.Stack `yaml:"stack"`
		}
		if err := yamlUnmarshal(src, &wrapped); err != nil {
			t.Fatal(err)
		}
		stack, err = &wrapped.Stack, nil
	}
	if err != nil {
		t.Fatal(err)
	}
	products, err := catalog.Resolve(cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]match.Constraint{}
	for _, p := range products {
		out[p.Name] = p.Constraint
	}
	return out
}

func TestMergeValuesFile(t *testing.T) {
	cfg := loadConfig(t)
	res := &Result{
		Helm: []*HelmEntry{
			{Release: config.HelmRelease{Repo: "https://argoproj.github.io/argo-helm", Chart: "argo-cd", Version: "10.9.7"}, Origins: []string{"argocd app argocd"}, ExposedBy: "HTTPRoute argocd.example.com"},
			{Release: config.HelmRelease{Repo: "https://grafana.github.io/helm-charts/", Chart: "loki", Version: "7.2.0", Versions: map[string]string{"loki": "3.6.9"}}, Overrides: map[string]string{"loki": "chart default 3.6.12"}},
			{Release: config.HelmRelease{Repo: "https://helm.goharbor.io", Chart: "harbor", Version: "1.20.0"}, Origins: []string{"argocd app harbor"}},
			{Release: config.HelmRelease{Repo: "https://charts.min.io/", Chart: "minio", Version: "5.4.0", Versions: map[string]string{
				"minio": "RELEASE.2025-04-22T22-12-26Z", "minio-mc": "RELEASE.2025-04-01T00-00-00Z"}}, ExposedBy: "LoadBalancer service minio"},
			{Release: config.HelmRelease{Repo: "https://charts.jetstack.io", Chart: "cert-manager", Version: "v1.20.6"}, Origins: []string{"argocd app cert-manager"}, ExposedBy: "HTTPRoute certs.example.com"},
		},
		Products: []*Product{
			{Name: "kubernetes", Versions: []string{"1.34.2"}},
			{Name: "cilium", Versions: []string{"v1.18.3"}, Origins: []string{"image"}},
			{Name: "postgresql", Versions: []string{"17.4"}, ExposedBy: "LoadBalancer service pg"},
			{Name: "grafana", Versions: []string{"13.0.5", "13.3.2"}},
			{Name: "keycloak", Versions: []string{"26.7.0"}, ExposedBy: "HTTPRoute sso.example.com"},
			{Name: "gitlab-ce", Versions: []string{"19.5.3"}, ExposedBy: "Ingress gitlab.example.com"},
			{Name: "containerd", Versions: []string{"2.2.3"}, Origins: []string{"container runtime on the nodes"}},
		},
	}
	out, changes, err := Merge(cfg, []byte(valuesFile), "", res, declaredOf(t, cfg, valuesFile, "stack"), day)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != valuesMerged {
		t.Errorf("merged file:\n%s\nwant:\n%s", out, valuesMerged)
	}
	got := strings.Join(changes, "\n")
	for _, want := range []string{
		"helm argo-cd: 10.9.2 -> 10.9.7",
		"helm harbor: added 1.20.0 (also listed in other versions; remove the stale ones, see stack diff)",
		"helm minio: versions.minio RELEASE.2025-01-01T00-00-00Z -> RELEASE.2025-04-22T22-12-26Z",
		"products.cilium: 1.18.2 -> 1.18.3",
		"note: products.gitlab-ce: kept exposure internal, although it is reachable through Ingress gitlab.example.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("changes lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "k8s") || strings.Contains(got, "kubernetes") {
		t.Errorf("kubernetes is allowed by >=1.33.0 and must not change:\n%s", got)
	}

	// Merging again changes nothing (notes are repeated).
	again, changes, err := Merge(cfg, out, "", res, declaredOf(t, cfg, string(out), "stack"), day)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(out) || len(changes) != 1 || !strings.HasPrefix(changes[0], "note: ") {
		t.Errorf("second merge changed %q:\n%s", changes, again)
	}
}

func TestMergePlainStackWithoutSections(t *testing.T) {
	cfg := loadConfig(t)
	src := "defaults:\n  exposure: internal\nproducts:\n  go: \"1.26.x\"\n"
	res := &Result{
		Helm:     []*HelmEntry{{Release: config.HelmRelease{Repo: "oci://ghcr.io/x", Chart: "dragonfly-operator", Version: "1.0"}, Origins: []string{"argocd app df"}}},
		Products: []*Product{{Name: "cilium", Versions: []string{"1.18.2"}, Origins: []string{"image"}}},
	}
	out, _, err := Merge(cfg, []byte(src), "", res, declaredOf(t, cfg, src, ""), day)
	if err != nil {
		t.Fatal(err)
	}
	want := "defaults:\n  exposure: internal\nproducts:\n  go: \"1.26.x\"\n  cilium: \"1.18.2\"  # image\n\nhelm:\n  - { repo: oci://ghcr.io/x, chart: dragonfly-operator, version: \"1.0\" }  # argocd app df\n" +
		"generated_at: \"2026-11-13\"  # inventory date; stack merge updates it\n"
	if string(out) != want {
		t.Errorf("merged:\n%s\nwant:\n%s", out, want)
	}
}

// A merge dates the inventory even when nothing else changed, in place:
// the value's style and the line's comment stay.
func TestMergeUpdatesGeneratedAt(t *testing.T) {
	cfg := loadConfig(t)
	src := "# our stack\ngenerated_at: '2026-10-01'   # last checked by hand\nproducts:\n  cilium: \"1.18.2\"  # image\n"
	res := &Result{Products: []*Product{{Name: "cilium", Versions: []string{"1.18.2"}}}}
	out, changes, err := Merge(cfg, []byte(src), "", res, declaredOf(t, cfg, src, ""), day)
	if err != nil {
		t.Fatal(err)
	}
	want := "# our stack\ngenerated_at: '2026-11-13'   # last checked by hand\nproducts:\n  cilium: \"1.18.2\"  # image\n"
	if string(out) != want || len(changes) != 1 || changes[0] != "generated_at: 2026-10-01 -> 2026-11-13" {
		t.Fatalf("merged (%q):\n%s\nwant:\n%s", changes, out, want)
	}
	stack, err := config.ParseStack(out)
	if err != nil || !stack.GeneratedAt.Equal(time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("generated_at: %v %v", err, stack)
	}
	if again, changes, _ := Merge(cfg, out, "", res, declaredOf(t, cfg, string(out), ""), day); string(again) != string(out) || len(changes) != 0 {
		t.Fatalf("same day: changed %v", changes)
	}
}

func TestFormatScalar(t *testing.T) {
	for v, want := range map[string]string{"1.14.2": "1.14.2", "17.4": `"17.4"`, "v1.2.3": "v1.2.3", "1": `"1"`, "a: b": `"a: b"`, "true": `"true"`} {
		if got := formatScalar(v, 0); got != want {
			t.Errorf("formatScalar(%q) = %s, want %s", v, got, want)
		}
	}
}

func yamlUnmarshal(s string, v any) error { return yaml.Unmarshal([]byte(s), v) }

func TestMergeOS(t *testing.T) {
	cfg := loadConfig(t)
	res := &Result{OS: &config.StackOS{Name: "debian", Release: "13", Kernel: "6.12.48 || 6.12.62", Criticality: "high"}}

	src := "stack:\n  products:\n    go: \"1.26.x\"\n\nresources: {}\n"
	out, changes, err := Merge(cfg, []byte(src), "", res, declaredOf(t, cfg, src, "stack"), day)
	if err != nil {
		t.Fatal(err)
	}
	want := "stack:\n  products:\n    go: \"1.26.x\"\n\n  os:\n    name: debian\n    release: \"13\"\n    kernel: \"6.12.48 || 6.12.62\"\n    criticality: high  # every workload runs on the nodes\n  generated_at: \"2026-11-13\"  # inventory date; stack merge updates it\n\nresources: {}\n"
	if string(out) != want || len(changes) != 2 {
		t.Fatalf("added os:\n%s\nwant:\n%s\nchanges %v", out, want, changes)
	}
	if again, changes, _ := Merge(cfg, out, "", res, declaredOf(t, cfg, string(out), "stack"), day); string(again) != string(out) || len(changes) != 0 {
		t.Fatalf("second merge changed %v", changes)
	}

	// One node rebooted into 6.12.62: a single version is replaced.
	src = "os:\n  name: debian\n  release: \"13\"\n  kernel: \"6.12.48\"\n"
	res.OS.Kernel = "6.12.62"
	out, _, err = Merge(cfg, []byte(src), "", res, declaredOf(t, cfg, src, ""), day)
	if err != nil || string(out) != "os:\n  name: debian\n  release: \"13\"\n  kernel: \"6.12.62\"\ngenerated_at: \"2026-11-13\"  # inventory date; stack merge updates it\n" {
		t.Fatalf("kernel update: %v\n%s", err, out)
	}
	// A new release replaces the kernel.
	res.OS = &config.StackOS{Name: "debian", Release: "14", Kernel: "6.18.3"}
	out, _, err = Merge(cfg, []byte(src), "", res, declaredOf(t, cfg, src, ""), day)
	if err != nil || string(out) != "os:\n  name: debian\n  release: \"14\"\n  kernel: \"6.18.3\"\ngenerated_at: \"2026-11-13\"  # inventory date; stack merge updates it\n" {
		t.Fatalf("release update: %v\n%s", err, out)
	}
}

// The local stack (top-level tenant and environment) is merged without
// --tenant and --environment; naming it as a tenant environment is refused
// before the cluster is read.
func TestCheckScopeRefusesTheLocalStack(t *testing.T) {
	values := []byte("stack:\n  tenant: vasops\n  environment: prod\n  products:\n    keycloak: \"26.1\"\n")
	scope := func(tenant, env string) []string { return []string{"tenants", tenant, "environments", env} }
	if err := CheckScope(values, "", scope("vasops", "prod")); err == nil || !strings.Contains(err.Error(), "merge it without --tenant and --environment") {
		t.Fatalf("want a hint to merge without --tenant, got %v", err)
	}
	for _, sc := range [][]string{scope("vasops", "stage"), scope("globex", "prod"), nil} {
		if err := CheckScope(values, "", sc); err != nil {
			t.Errorf("%v: %v", sc, err)
		}
	}
	if err := CheckScope([]byte("products: {keycloak: '1'}\n"), "", scope("vasops", "prod")); err != nil {
		t.Errorf("a stack without a named local stack: %v", err)
	}
}
