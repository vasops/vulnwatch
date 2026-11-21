package report_test

import (
	"testing"

	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestUpgrades(t *testing.T) {
	ups := reporttest.Sample().Upgrades()
	if len(ups) != 2 {
		t.Fatalf("%+v", ups)
	}
	// argocd 3.x: GHSA fixed in 3.1.8/3.0.15, CVE-2026-0800 fixed in 3.1.2.
	if a := ups[0]; a.Product != "argocd" || a.Constraint != "3.x" || a.UpgradeTo != "3.1.2" || a.Unfixed != 0 {
		t.Fatalf("argocd: %+v", a)
	}
	// keycloak 26.x: CVE-2026-1001 fixed in 26.1.4, CVE-2026-0900 has no fix.
	if k := ups[1]; k.Product != "keycloak" || k.UpgradeTo != "26.1.4" || k.Unfixed != 1 {
		t.Fatalf("keycloak: %+v", k)
	}
}
