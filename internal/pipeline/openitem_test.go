package pipeline

import (
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/internal/triage"
)

// Still-open and history items keep EPSS, so their P1 card shows it.
func TestOpenItemKeepsEPSS(t *testing.T) {
	c, _ := match.ParseConstraint("20.0.3")
	p := catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high"}
	f := finding.Finding{ID: "CVE-2025-1", Product: "keycloak", Severity: "critical", CVSS: 9.8, KEV: true, EPSS: 0.42,
		Affected: []finding.Range{{Introduced: "20.0.0", Fixed: "21.0.0"}}, Fixed: []string{"21.0.0"}}
	it, st := openItem(p, f.ID, state.Detail{Finding: f, Priority: "P1", Relevant: "yes", Method: triage.MethodLLM}, time.Now(), false)
	if st != openListed || it.EPSS != 0.42 || !it.KEV {
		t.Fatalf("%d %+v", st, it)
	}
}
