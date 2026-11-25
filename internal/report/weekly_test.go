package report

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/triage"
)

func weeklyReport(t *testing.T) Report {
	t.Helper()
	now := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	c, err := match.ParseConstraint("26.1.0")
	if err != nil {
		t.Fatal(err)
	}
	product := func(tenant, env string) catalog.Product {
		return catalog.Product{Name: "keycloak", Constraint: c, Scope: config.Scope{Tenant: tenant, Environment: env, Remote: true}}
	}
	ps := []catalog.Product{product("acme", "prod"), product("acme", "stage"), product("globex", "test")}
	days := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	open := func(tenant, env, id, prio string, first time.Time) OpenItem {
		return OpenItem{ID: id, Product: "keycloak", Tenant: tenant, Environment: env, Constraint: "26.1.0", Priority: prio, FirstReported: first}
	}
	closed := func(tenant, env, id, reason string) ClosedItem {
		return ClosedItem{ID: id, Product: "keycloak", Tenant: tenant, Environment: env, Priority: "P2", Reason: reason, ClosedAt: days(1), FirstReported: days(30)}
	}
	m := Meta{
		Mode: ModeRun, GeneratedAt: now, Since: days(1), Until: now, Products: ps,
		Open: []OpenItem{
			open("acme", "prod", "CVE-2025-1", "P3", days(200)),
			open("globex", "test", "CVE-2025-1", "P3", days(100)),
			open("acme", "prod", "CVE-2025-2", "P2", days(150)),
			open("acme", "stage", "CVE-2025-3", "P4", days(140)),
			open("globex", "test", "CVE-2025-4", "P2", days(130)),
			open("globex", "test", "CVE-2025-5", "P1", days(130)),
			open("acme", "prod", "CVE-2025-6", "P2", days(120)),
			open("acme", "stage", "CVE-2026-7", "P2", days(3)),
		},
		Weekly: &Weekly{From: days(7), Until: now, Closed: []ClosedItem{
			closed("acme", "prod", "CVE-2026-10", ClosedFixed),
			closed("globex", "test", "CVE-2026-11", ClosedRejected),
			closed("acme", "old", "CVE-2026-12", ClosedRemoved), // environment no longer in the stack
		}},
	}
	entry := finding.Finding{ID: "CVE-2026-8", Product: "acme/prod/keycloak", Title: "new one", Match: "affected"}
	return Build(m, []Entry{{Finding: entry, Product: ps[0], Triage: triage.Result{Relevant: "yes", Priority: "P1"}}})
}

func ids[T any](items []T, id func(T) string) string {
	var out []string
	for _, it := range items {
		out = append(out, id(it))
	}
	return strings.Join(out, " ")
}

func openID(it OpenItem) string     { return it.Scope + ":" + it.ID }
func closedID(it ClosedItem) string { return it.Scope + ":" + it.ID }

func TestWeekly(t *testing.T) {
	r := weeklyReport(t)
	w := r.Weekly
	if w == nil {
		t.Fatal("no weekly data")
	}
	if got := ids(w.New, openID); got != "acme/prod:CVE-2026-8 acme/stage:CVE-2026-7" {
		t.Errorf("new: %s", got)
	}
	// Five findings, CVE-2025-1 in two environments; ties by priority.
	if got := ids(w.Oldest, openID); got != "acme/prod:CVE-2025-1 acme/prod:CVE-2025-2 acme/stage:CVE-2025-3 globex/test:CVE-2025-5 globex/test:CVE-2025-4 globex/test:CVE-2025-1" {
		t.Errorf("oldest: %s", got)
	}
	if len(OpenFindings(w.Oldest, func(OpenItem) string { return "" })) != MaxOldest {
		t.Errorf("oldest findings: %+v", w.Oldest)
	}
	if got := sum(w.OpenCounts); got != 9 || w.OpenCounts[0].Count != 2 {
		t.Errorf("open counts: %+v", w.OpenCounts)
	}
	if got := ids(w.Closed, closedID); got != "acme/old:CVE-2026-12 acme/prod:CVE-2026-10 globex/test:CVE-2026-11" {
		t.Errorf("closed: %s", got)
	}
}

func sum(cs []PriorityCount) int {
	n := 0
	for _, c := range cs {
		n += c.Count
	}
	return n
}

func TestWeeklyForScopes(t *testing.T) {
	r := weeklyReport(t)
	acme := func(s ScopeInfo) bool { return s.Tenant == "acme" }
	tests := []struct {
		name               string
		keep               func(ScopeInfo) bool
		def                bool
		new, closed, older string
		open               int
	}{
		{"tenant route", acme, false, "acme/prod:CVE-2026-8 acme/stage:CVE-2026-7", "acme/prod:CVE-2026-10",
			"acme/prod:CVE-2025-1 acme/prod:CVE-2025-2 acme/stage:CVE-2025-3 acme/prod:CVE-2025-6", 6},
		{"default route gets the removed environment", func(s ScopeInfo) bool { return !acme(s) }, true, "",
			"acme/old:CVE-2026-12 globex/test:CVE-2026-11", "globex/test:CVE-2025-5 globex/test:CVE-2025-4 globex/test:CVE-2025-1", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := r.ForScopes(tt.keep, tt.def).Weekly
			if got := ids(w.New, openID); got != tt.new {
				t.Errorf("new: %s", got)
			}
			if got := ids(w.Closed, closedID); got != tt.closed {
				t.Errorf("closed: %s", got)
			}
			if got := ids(w.Oldest, openID); got != tt.older {
				t.Errorf("oldest: %s", got)
			}
			if got := sum(w.OpenCounts); got != tt.open {
				t.Errorf("open: %+v", w.OpenCounts)
			}
		})
	}
	if r.ForScopes(acme, false).Weekly == r.Weekly {
		t.Error("ForScopes must not share the weekly data")
	}
	r.Weekly = nil
	if r.ForScopes(acme, false).Weekly != nil {
		t.Error("no weekly data, none after ForScopes")
	}
}

// Findings first reported in the window are under New only; with nothing
// older, Oldest is empty.
func TestWeeklyOldestLeavesOutNew(t *testing.T) {
	r := weeklyReport(t)
	for _, it := range r.Weekly.Oldest {
		if !it.FirstReported.Before(r.Weekly.From) {
			t.Errorf("new finding under oldest: %+v", it)
		}
	}
	onlyNew := r.ForScopes(func(s ScopeInfo) bool { return s.Environment == "stage" }, false)
	onlyNew.Open = slices.DeleteFunc(onlyNew.Open, func(it OpenItem) bool { return it.ID != "CVE-2026-7" })
	if w := onlyNew.ForScopes(func(ScopeInfo) bool { return true }, false).Weekly; len(w.Oldest) != 0 || len(w.New) != 1 {
		t.Errorf("oldest %+v, new %+v", w.Oldest, w.New)
	}
}

func TestWeeklyDays(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	tests := []struct {
		until time.Time
		want  string
	}{
		{time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC), "16 – 23 Nov 2026"},
		{time.Date(2026, 12, 5, 6, 0, 0, 0, time.UTC), "28 Nov – 5 Dec 2026"},
		{time.Date(2027, 1, 4, 6, 0, 0, 0, time.UTC), "28 Dec 2026 – 4 Jan 2027"},
		{time.Date(2026, 11, 23, 0, 30, 0, 0, cet), "16 – 23 Nov 2026"}, // 15 – 22 Nov in UTC
	}
	for _, tt := range tests {
		w := &Weekly{From: tt.until.AddDate(0, 0, -7).UTC(), Until: tt.until}
		if got := w.Days(); got != tt.want {
			t.Errorf("%v: %s, want %s", tt.until, got, tt.want)
		}
	}
}

func TestClosedFindingsGroupByReason(t *testing.T) {
	items := []ClosedItem{
		{ID: "CVE-2026-1", Product: "keycloak", Tenant: "acme", Environment: "dev", Scope: "acme/dev", Reason: ClosedFixed},
		{ID: "CVE-2026-1", Product: "keycloak", Tenant: "acme", Environment: "prod", Scope: "acme/prod", Reason: ClosedFixed, Priority: "P1"},
		{ID: "CVE-2026-1", Product: "keycloak", Tenant: "globex", Environment: "test", Scope: "globex/test", Reason: ClosedRemoved},
	}
	fs := ClosedFindings(items)
	if len(fs) != 1 || fs[0].Change != "" || len(fs[0].Lines) != 2 || fs[0].Lines[0].Names() != "acme: dev, prod" || fs[0].Lines[1].Change != ClosedRemoved {
		t.Fatalf("%+v", fs)
	}
	if fs := ClosedFindings(items[:2]); fs[0].Change != ClosedFixed || len(fs[0].Scopes) != 2 {
		t.Fatalf("shared reason: %+v", fs)
	}
}
