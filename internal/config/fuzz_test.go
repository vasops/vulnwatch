package config

import "testing"

// stack.yaml is written by people and by stack merge.
func FuzzParseStack(f *testing.F) {
	for _, s := range []string{
		"products: {keycloak: '26.7.0'}\n",
		"helm: [{repo: https://charts.example, chart: x, version: 1.0.0}]\n",
		"os: {name: debian, release: '13', kernel: 6.12.48}\n",
		"tenants: {acme: {environments: {prod: {products: {keycloak: '1'}}}}}\n",
		"tenant: Bad Name\n", "products: [1, 2]\n", "&a [*a]\n", "",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseStack(b)
		if err != nil || s == nil {
			return
		}
		for _, sc := range s.Scopes() {
			_ = sc.Scope.Prefix()
		}
	})
}
