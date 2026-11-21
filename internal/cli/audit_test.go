package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/pipeline"
)

func TestWriteAuditIncomplete(t *testing.T) {
	warnings := []string{"ghsa/argocd: HTTP 502", "nvd/keycloak: timeout", "osv/keycloak: connection refused", "osv/keycloak-x: HTTP 500"}
	tests := []struct {
		name   string
		r      pipeline.AuditProduct
		want   []string
		absent []string
	}{
		{"complete, nothing found", pipeline.AuditProduct{Product: "keycloak", Checked: 3, Complete: true},
			[]string{"nothing affects this version"}, []string{"INCOMPLETE"}},
		{"incomplete, nothing found", pipeline.AuditProduct{Product: "keycloak", Checked: 3},
			[]string{"nothing found in the sources that answered", "INCOMPLETE: nvd, osv failed"}, []string{"nothing affects", "ghsa"}},
		{"incomplete, affected", pipeline.AuditProduct{Product: "keycloak", Checked: 3, Affected: 1},
			[]string{"1 affected", "INCOMPLETE: nvd, osv failed"}, []string{"nothing"}},
		{"incomplete, no warning names the source", pipeline.AuditProduct{Product: "grafana"},
			[]string{"INCOMPLETE: a source failed"}, []string{"nothing affects"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b bytes.Buffer
			writeAudit(&b, []pipeline.AuditProduct{tt.r}, warnings)
			for _, s := range tt.want {
				if !strings.Contains(b.String(), s) {
					t.Errorf("missing %q in:\n%s", s, b.String())
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(b.String(), s) {
					t.Errorf("unexpected %q in:\n%s", s, b.String())
				}
			}
		})
	}
}
