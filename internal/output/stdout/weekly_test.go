package stdout

import (
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func weeklyReport(open []report.OpenItem, closed []report.ClosedItem) report.Report {
	now := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	c, _ := match.ParseConstraint("1.0.0")
	var ps []catalog.Product
	for _, env := range []string{"dev", "prod", "stage"} {
		ps = append(ps, catalog.Product{Name: "keycloak", Constraint: c, Scope: config.Scope{Tenant: "acme", Environment: env, Remote: true}})
	}
	for i := range open {
		open[i].FirstReported = now.AddDate(0, 0, -open[i].DaysOpen)
	}
	return report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now, Products: ps,
		Open: open, Weekly: &report.Weekly{From: now.AddDate(0, 0, -7), Until: now, Closed: closed}}, nil)
}

func TestWeeklyGolden(t *testing.T) {
	item := func(env, product, id, prio, title string, days int) report.OpenItem {
		return report.OpenItem{ID: id, Product: product, Tenant: "acme", Environment: env, Constraint: "1.0.0", Priority: prio, Title: title, DaysOpen: days}
	}
	closed := func(env, product, id, reason string) report.ClosedItem {
		return report.ClosedItem{ID: id, Product: product, Tenant: "acme", Environment: env, Priority: "P2", Reason: reason}
	}
	pg := item("prod", "postgresql", "CVE-2025-44444", "P2", "", 142)
	pg.Action = "Upgrade to 17.6 or later."
	r := weeklyReport([]report.OpenItem{
		item("dev", "debian-13-kernel", "CVE-2026-98432", "P1", "ipv4: free inet_opt and ireq_opt after an RCU grace period", 3),
		item("prod", "debian-13-kernel", "CVE-2026-98432", "P1", "ipv4: free inet_opt and ireq_opt after an RCU grace period", 3),
		item("prod", "keycloak", "CVE-2026-11111", "P2", "Open redirect in the login flow", 2),
		pg,
	}, []report.ClosedItem{
		closed("dev", "keycloak", "CVE-2026-22222", report.ClosedFixed),
		closed("prod", "keycloak", "CVE-2026-22222", report.ClosedFixed),
		closed("stage", "grafana", "CVE-2026-33333", report.ClosedRemoved),
		closed("stage", "argocd", "CVE-2026-44444", report.ClosedRejected),
		closed("prod", "argocd", "CVE-2026-44444", report.ClosedNotRelevant),
	})
	golden(t, "weekly.golden", New(nil, false).Text(r))
	golden(t, "weekly_nothing.golden", New(nil, false).Text(weeklyReport(nil, nil)))
}

func TestWeeklyOnlyWhenPresent(t *testing.T) {
	if out := New(nil, false).Text(reporttest.Sample()); strings.Contains(out, "Weekly") {
		t.Fatalf("weekly section without weekly data:\n%s", out)
	}
	r := weeklyReport(nil, nil)
	without := r
	without.Weekly = nil
	with := New(nil, false).Text(r)
	if !strings.HasPrefix(with, New(nil, false).Text(without)) || !strings.Contains(with, "== Weekly report · 16 – 23 Nov 2026 ==") {
		t.Fatalf("the weekly section follows the report:\n%s", with)
	}
}
