package config

import (
	"strings"
	"testing"
	"time"
)

func TestStackScopes(t *testing.T) {
	s, err := ParseStack([]byte(`
tenant: vasops
environment: prod
generated_at: 2026-11-02
defaults: {min_cvss: 5.0}
products: {keycloak: '26.7.0'}
tenants:
  acme:
    defaults: {exposure: internet}
    slack: {channel: C-ACME}
    environments:
      stage:
        products: {keycloak: '26.0.1'}
      prod:
        generated_at: "2026-10-01"
        defaults: {criticality: high}
        slack: {alert_channel: C-ACME-ALERTS}
        products: {keycloak: '25.0.6'}
`))
	if err != nil {
		t.Fatal(err)
	}
	sc := s.Scopes()
	var names []string
	for _, x := range sc {
		names = append(names, x.Scope.String()+"@"+x.Scope.Prefix())
	}
	if strings.Join(names, " ") != "vasops/prod@ acme/prod@acme/prod/ acme/stage@acme/stage/" {
		t.Fatalf("scopes: %v", names)
	}
	if sc[0].Scope.Remote || !sc[1].Scope.Remote || sc[1].Path != "tenants.acme.environments.prod" {
		t.Fatalf("local/remote: %+v", sc)
	}
	prod := sc[1]
	if d := prod.Stack.Defaults; *d.MinCVSS != 5.0 || d.Exposure != "internet" || d.Criticality != "high" {
		t.Errorf("defaults layer stack, tenant, environment: %+v", d)
	}
	if prod.Scope.Slack != (SlackRoute{Channel: "C-ACME", AlertChannel: "C-ACME-ALERTS"}) || sc[2].Scope.Slack.Channel != "C-ACME" {
		t.Errorf("slack: environment over tenant: %+v %+v", prod.Scope.Slack, sc[2].Scope.Slack)
	}
	if !sc[0].Scope.GeneratedAt.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) ||
		!prod.Scope.GeneratedAt.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) || !sc[2].Scope.GeneratedAt.IsZero() {
		t.Errorf("generated_at per scope: %v %v %v", sc[0].Scope.GeneratedAt, prod.Scope.GeneratedAt, sc[2].Scope.GeneratedAt)
	}

	// Without a top-level stack: tenants only.
	s, err = ParseStack([]byte("tenants: {acme: {environments: {prod: {products: {keycloak: '26.7.0'}}}}}\n"))
	if err != nil || len(s.Scopes()) != 1 || s.Scopes()[0].Scope.String() != "acme/prod" {
		t.Fatalf("tenants only: %v %+v", err, s)
	}
}

func TestStackTenantErrors(t *testing.T) {
	cases := map[string]string{
		"tenants: {Acme: {environments: {prod: {products: {keycloak: '1'}}}}}":                                                             "tenants.Acme: want lowercase",
		"tenants: {acme: {environments: {}}}":                                                                                              "tenants.acme: environments: at least one",
		"tenants: {acme: {environments: {prod: {}}}}":                                                                                      "tenants.acme.environments.prod: products, helm and os must not all be empty",
		"tenants: {acme: {environments: {prod: {products: {keycloak: ''}}}}}":                                                              "tenants.acme.environments.prod.products.keycloak: version is required",
		"tenant: acme\nenvironment: prod\nproducts: {keycloak: '1'}\ntenants: {acme: {environments: {prod: {products: {keycloak: '1'}}}}}": "is the local stack's name",
		"tenants: {acme: {environments: {prod: {os: {name: windows, release: '1', kernel: '1'}}}}}":                                        "tenants.acme.environments.prod.os.name",
		"tenants: {acme: {environments: {prod: {generated_at: 13.11.2026, products: {keycloak: '1'}}}}}":                                   "want a date like 2026-11-13",
		"generated_at: [2026-11-13]\nproducts: {keycloak: '1'}":                                                                            "want a date like 2026-11-13",
	}
	for in, want := range cases {
		_, err := ParseStack([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", in, err, want)
		}
	}
}
