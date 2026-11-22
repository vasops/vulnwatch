// Package reporttest provides a fixed report for renderer golden tests.
package reporttest

import (
	_ "embed"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

// Links and warnings live in fixtures.txt: non-test Go code holds no URL literals.
//
//go:embed fixtures.txt
var fixtures string

func fixture(i int) string { return strings.Split(strings.TrimSpace(fixtures), "\n")[i] }

func product(name, constraint, exposure, criticality string) catalog.Product {
	c, err := match.ParseConstraint(constraint)
	if err != nil {
		panic(err)
	}
	return catalog.Product{Name: name, Constraint: c, Exposure: exposure, Criticality: criticality, MinCVSS: 4}
}

// Sample returns a deterministic report covering every renderer feature.
func Sample() report.Report {
	kc := product("keycloak", "26.x", "internet", "high")
	ac := product("argocd", "3.x", "internal", "medium")
	lh := product("longhorn", "1.8.1", "internal", "medium")
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	entries := []report.Entry{
		{
			Finding: finding.Finding{
				ID: "CVE-2026-1001", Aliases: []string{"GHSA-abcd-efgh-ijkl"}, Product: "keycloak",
				Title: "Account takeover via crafted <redirect_uri>", CVSS: 9.8, Severity: "critical",
				KEV: true, EPSS: 0.91234, EPSSPercentile: 0.995, Fixed: []string{"26.1.4"}, Match: "affected",
				References: []string{fixture(0), fixture(1)},
			},
			Product: kc,
			Triage: triage.Result{Relevant: "yes", Priority: "P1", Method: triage.MethodLLM,
				Summary:   "An attacker can take over accounts by abusing redirect URI validation.",
				Reasoning: "Internet-facing, all 26.x before 26.1.4 affected, exploited in the wild.",
				Action:    "Upgrade to 26.1.4 today."},
		},
		{
			Finding: finding.Finding{
				ID: "GHSA-xxxx-yyyy-zzzz", Product: "argocd", Title: "Repo server path traversal",
				CVSS: 7.5, Severity: "high", Fixed: []string{"3.1.8", "3.0.15"}, Match: "unknown",
				References: []string{fixture(2)},
			},
			Product: ac,
			Change:  "fixed version released: 3.1.8",
			Triage: triage.Result{Relevant: "uncertain", Priority: "P3", Method: triage.MethodFallback,
				Summary: "Repo server path traversal", Reasoning: "Rule-based.",
				Action: "Check the deployed version; upgrade to a fixed version (3.1.8, 3.0.15) if affected.",
				Note:   "not triaged: LLM output invalid or unavailable"},
		},
		{
			Finding: finding.Finding{ID: "CVE-2026-2002", Product: "longhorn", Title: "Not affecting us", CVSS: 6.1, Match: "not_affected"},
			Product: lh,
			Triage:  triage.Result{Relevant: "no", Priority: "P4", Method: triage.MethodRules, Summary: "n/a", Reasoning: "n/a", Action: "No action."},
		},
	}
	return report.Build(report.Meta{
		Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-48 * time.Hour), Until: now,
		Products: []catalog.Product{ac, kc, lh}, BelowThreshold: 2, Unchanged: 5,
		Warnings: []string{fixture(3)},
		Open: []report.OpenItem{
			{ID: "CVE-2026-0800", Product: "argocd", Constraint: "3.x", Title: "Repo server <script> injection",
				CVSS: 6.5, Severity: "medium", Match: "unknown", Priority: "P3", Fixed: []string{"3.1.2"},
				FirstReported: now.AddDate(0, 0, -30)},
			{ID: "CVE-2026-0900", Product: "keycloak", Constraint: "26.x", Title: "Token leak in admin console",
				CVSS: 8.8, Severity: "high", KEV: true, Match: "affected", Priority: "P1",
				FirstReported: now.AddDate(0, 0, -14), Link: fixture(1), Aliases: []string{"GHSA-mnop-qrst-uvwx"}},
		},
		OpenUnknown: 3,
		Links:       report.AdvisoryLinks{NVD: fixture(4), GitHub: fixture(5)},
		Baselines: []report.BaselineSummary{
			{Product: "longhorn", Constraint: "1.8.1", Reason: report.BaselineNew, Checked: 12, Complete: true},
			{Product: "keycloak", Constraint: "26.x", Reason: report.BaselineVersionChanged, Checked: 412, Affected: 3, Unknown: 2, KEV: 1, Complete: true},
			{Product: "argocd", Constraint: "3.x", Reason: report.BaselineNew, Checked: 80, Complete: false},
		},
	}, entries)
}

// Empty returns a report with no findings.
func Empty() report.Report {
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	return report.Build(report.Meta{
		Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now,
		Products: []catalog.Product{product("keycloak", "26.x", "internet", "high")},
	}, nil)
}
