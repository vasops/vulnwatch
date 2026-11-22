package discover

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/vasops/vulnwatch/internal/config"
)

func TestMergeScope(t *testing.T) {
	cfg := loadConfig(t)
	src := `stack:
  products:
    keycloak: "26.7.0"
`
	acme := []string{"tenants", "acme", "environments", "prod"}
	res := &Result{Context: "acme-prod", Products: []*Product{{Name: "keycloak", Versions: []string{"25.0.6"}}, {Name: "kubernetes", Versions: []string{"1.34.2"}}}}

	// A missing tenant: tenants, acme, environments and prod are added.
	out, changes, err := MergeScope(cfg, []byte(src), "", acme, res, nil, day)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !strings.Contains(changes[0], "tenants.acme.environments.prod: added from context acme-prod") {
		t.Fatalf("changes: %v", changes)
	}
	stack := parseValues(t, out)
	e := stack.Tenants["acme"].Environments["prod"]
	if stack.Products["keycloak"].Version != "26.7.0" || e.Products["keycloak"].Version != "25.0.6" || e.Products["kubernetes"].Version != "1.34.2" {
		t.Fatalf("merged:\n%s", out)
	}
	// The environment is dated, the local stack (not merged) is not.
	if e.GeneratedAt.Format(time.DateOnly) != "2026-11-13" || !stack.GeneratedAt.IsZero() {
		t.Fatalf("generated_at:\n%s", out)
	}

	// A second environment of the same tenant goes under environments.
	stage := []string{"tenants", "acme", "environments", "stage"}
	out, _, err = MergeScope(cfg, out, "", stage, &Result{Context: "acme-stage", Products: []*Product{{Name: "keycloak", Versions: []string{"26.0.1"}}}}, nil, day)
	if err != nil {
		t.Fatal(err)
	}
	stack = parseValues(t, out)
	if v := stack.Tenants["acme"].Environments["stage"].Products["keycloak"].Version; v != "26.0.1" || len(stack.Tenants["acme"].Environments) != 2 {
		t.Fatalf("second environment:\n%s", out)
	}

	// An existing environment is merged like the top-level stack, a day
	// later: its generated_at follows, the other environment's stays.
	out, changes, err = MergeScope(cfg, out, "", acme, &Result{Context: "acme-prod", Products: []*Product{{Name: "keycloak", Versions: []string{"26.7.5"}}}}, nil, day.AddDate(0, 0, 1))
	if err != nil {
		t.Fatal(err)
	}
	stack = parseValues(t, out)
	if v := stack.Tenants["acme"].Environments["prod"].Products["keycloak"].Version; v != "26.7.5" || stack.Products["keycloak"].Version != "26.7.0" {
		t.Fatalf("existing environment (%v):\n%s", changes, out)
	}
	if prod, stage := stack.Tenants["acme"].Environments["prod"].GeneratedAt, stack.Tenants["acme"].Environments["stage"].GeneratedAt; prod.Format(time.DateOnly) != "2026-11-14" ||
		stage.Format(time.DateOnly) != "2026-11-13" || !strings.Contains(strings.Join(changes, "\n"), "generated_at: 2026-11-13 -> 2026-11-14") {
		t.Fatalf("generated_at (%v):\n%s", changes, out)
	}
}

func parseValues(t *testing.T, b []byte) *config.Stack {
	t.Helper()
	var v struct {
		Stack yaml.Node `yaml:"stack"`
	}
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(&v.Stack)
	if err != nil {
		t.Fatal(err)
	}
	s, err := config.ParseStack(raw)
	if err != nil {
		t.Fatalf("%v:\n%s", err, b)
	}
	return s
}
