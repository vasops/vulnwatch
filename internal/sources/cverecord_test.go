package sources

import (
	"testing"

	"github.com/vasops/vulnwatch/internal/finding"
)

func TestCNAVersion(t *testing.T) {
	tests := []struct {
		name                    string
		version, lt, lte, vtype string
		wantRange               finding.Range
		wantExact               string
		wantOK                  bool
	}{
		{"less than", "2.4.0", "2.4.62", "", "semver", finding.Range{Introduced: "2.4.0", Fixed: "2.4.62"}, "", true},
		{"through", "2.4.55", "", "2.4.70", "semver", finding.Range{Introduced: "2.4.55", LastAffected: "2.4.70"}, "", true},
		{"from the beginning", "0", "1.5.0", "", "custom", finding.Range{Fixed: "1.5.0"}, "", true},
		{"n/a start", "n/a", "", "3.1", "", finding.Range{LastAffected: "3.1"}, "", true},
		{"open end", "2.0", "*", "", "semver", finding.Range{Introduced: "2.0"}, "", true},
		{"range in the version", ">= 1.2.0, < 1.2.5", "", "", "", finding.Range{Introduced: "1.2.0", Fixed: "1.2.5"}, "", true},
		{"exact", "5.6.1", "", "", "", finding.Range{}, "5.6.1", true},
		{"git", "1a2b3c", "4d5e6f", "", "git", finding.Range{}, "", false},
		{"no version", "n/a", "", "", "", finding.Range{}, "", false},
		{"not a version", "unknown release", "", "", "", finding.Range{}, "", false},
	}
	for _, tt := range tests {
		r, exact, ok := CNAVersion(tt.version, tt.lt, tt.lte, tt.vtype)
		if r != tt.wantRange || exact != tt.wantExact || ok != tt.wantOK {
			t.Errorf("%s: got %+v %q %v", tt.name, r, exact, ok)
		}
	}
}

func TestCPEMatches(t *testing.T) {
	tests := []struct {
		sel, crit string
		want      bool
	}{
		{"cpe:2.3:a:grafana:grafana", "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", true},
		{"cpe:2.3:a:grafana:grafana", "cpe:2.3:a:grafana:loki:*:*:*:*:*:*:*:*", false},
		{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", true},
		{"cpe:2.3:a:gitlab:gitlab:*:*:*:*:community:*:*:*", "cpe:2.3:a:gitlab:gitlab:*:*:*:*:enterprise:*:*:*", false},
		{"cpe:2.3:a:redhat:keycloak", "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*", false},
	}
	for _, tt := range tests {
		if got := CPEMatches(tt.sel, tt.crit); got != tt.want {
			t.Errorf("%s vs %s: got %v", tt.sel, tt.crit, got)
		}
	}
}
