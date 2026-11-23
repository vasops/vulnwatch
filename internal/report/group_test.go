package report

import (
	"reflect"
	"testing"
)

func scopedItem(tenant, env, product, id, constraint, prio, change, action string) Item {
	return Item{
		ID: id, Product: product, Tenant: tenant, Environment: env, Scope: tenant + "/" + env,
		Constraint: constraint, Priority: prio, Change: change, Action: action, Title: "title " + tenant + env,
	}
}

func lineNames(f Finding[Item]) []string {
	var out []string
	for _, l := range f.Lines {
		out = append(out, l.Names()+" | "+l.Constraint)
	}
	return out
}

func TestFindingsFiveVersionGroupsEightScopes(t *testing.T) {
	const id, prod, act = "CVE-2026-0001", "debian-13-kernel", "Upgrade the kernel"
	items := []Item{
		scopedItem("acme", "dev", prod, id, "6.12.95", "P1", "new", act),
		scopedItem("globex", "test", prod, id, "6.12.95", "P1", "new", act),
		scopedItem("acme", "prod", prod, id, "6.12.95, 6.12.101", "P1", "new", act),
		scopedItem("initech", "dev", prod, id, "6.12.57", "P1", "new", act),
		scopedItem("initech", "stage", prod, id, "6.12.57", "P1", "new", act),
		scopedItem("initech", "prod", prod, id, "6.12.62", "P1", "new", act),
		scopedItem("umbrella", "prod", prod, id, "6.12.88", "P1", "new", act),
		scopedItem("umbrella", "stage", prod, id, "6.12.88", "P1", "new", act),
	}
	fs := Findings(items)
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	f := fs[0]
	want := []string{
		"acme: dev; globex: test | 6.12.95",
		"acme: prod | 6.12.95, 6.12.101",
		"initech: dev, stage | 6.12.57",
		"initech: prod | 6.12.62",
		"umbrella: prod, stage | 6.12.88",
	}
	if got := lineNames(f); !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
	if f.Change != "new" || f.Action != act || f.Priority != "P1" {
		t.Errorf("finding = %+v", f)
	}
	c := Count(fs)
	if c.Findings != 1 || c.Scopes != 8 {
		t.Errorf("counts = %+v, want 1 finding in 8 scopes", c)
	}
	wantPrio := []PriorityCount{{"P1", 1}, {"P2", 0}, {"P3", 0}, {"P4", 0}}
	if !reflect.DeepEqual(c.ByPriority, wantPrio) {
		t.Errorf("by priority = %v, want %v", c.ByPriority, wantPrio)
	}
}

func TestFindingsMixedPriorities(t *testing.T) {
	items := []Item{
		scopedItem("acme", "dev", "kernel", "CVE-1", "6.1", "P2", "new", "a"),
		scopedItem("acme", "prod", "kernel", "CVE-1", "6.1", "P1", "new", "a"),
	}
	f := Findings(items)[0]
	if f.Priority != "P1" {
		t.Errorf("priority = %q, want P1", f.Priority)
	}
	if f.Representative.Environment != "prod" {
		t.Errorf("representative = %s, want the P1 scope", f.Representative.Scope)
	}
	if len(f.Lines) != 2 || f.Lines[0].Priority != "P2" || f.Lines[1].Priority != "P1" {
		t.Errorf("lines = %+v, want separate P2 and P1 lines in order of appearance", f.Lines)
	}
	c := Count(Findings(items))
	if c.ByPriority[0].Count != 1 || c.ByPriority[1].Count != 0 {
		t.Errorf("findings are counted by highest priority only: %v", c.ByPriority)
	}
}

func TestFindingsRepresentativeIsFirstAmongEqualPriorities(t *testing.T) {
	f := Findings([]Item{
		scopedItem("acme", "dev", "p", "CVE-1", "1", "P3", "new", ""),
		scopedItem("globex", "dev", "p", "CVE-1", "2", "P2", "new", ""),
		scopedItem("initech", "dev", "p", "CVE-1", "3", "P2", "new", ""),
	})[0]
	if f.Representative.Tenant != "globex" {
		t.Errorf("representative = %s, want globex", f.Representative.Scope)
	}
}

func TestFindingsAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []string // per scope, in order; the first has the highest priority
		prio    []string
		want    string
	}{
		{"most common", []string{"a", "b", "b"}, []string{"P1", "P1", "P1"}, "b"},
		{"tie prefers the representative's", []string{"a", "b"}, []string{"P2", "P1"}, "b"},
		{"three-way tie, representative among the tied", []string{"x", "a", "b"}, []string{"P1", "P2", "P2"}, "x"},
		{"empty actions ignored", []string{"", "a"}, []string{"P1", "P1"}, "a"},
		{"all empty", []string{"", ""}, []string{"P1", "P1"}, ""},
	}
	envs := []string{"e1", "e2", "e3", "e4", "e5", "e6"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var items []Item
			for i, a := range tc.actions {
				items = append(items, scopedItem("acme", envs[i], "p", "CVE-1", "1", tc.prio[i], "new", a))
			}
			if got := Findings(items)[0].Action; got != tc.want {
				t.Errorf("action = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFindingsTieOutsideRepresentative(t *testing.T) {
	// The representative's action "r" has one vote; a and b tie at two, so
	// the tied action that appears first wins.
	items := []Item{
		scopedItem("acme", "e1", "p", "CVE-1", "1", "P1", "new", "r"),
		scopedItem("acme", "e2", "p", "CVE-1", "1", "P2", "new", "a"),
		scopedItem("acme", "e3", "p", "CVE-1", "1", "P2", "new", "b"),
		scopedItem("acme", "e4", "p", "CVE-1", "1", "P2", "new", "b"),
		scopedItem("acme", "e5", "p", "CVE-1", "1", "P2", "new", "a"),
	}
	if got := Findings(items)[0].Action; got != "a" {
		t.Errorf("action = %q, want a", got)
	}
}

func TestFindingsDifferentChange(t *testing.T) {
	items := []Item{
		scopedItem("acme", "dev", "p", "CVE-1", "1", "P1", "new", "a"),
		scopedItem("acme", "prod", "p", "CVE-1", "1", "P1", "priority P2 -> P1", "a"),
		scopedItem("globex", "dev", "p", "CVE-1", "1", "P1", "new", "a"),
	}
	f := Findings(items)[0]
	if f.Change != "" {
		t.Errorf("shared change = %q, want none", f.Change)
	}
	if len(f.Lines) != 2 {
		t.Fatalf("lines = %+v, want 2", f.Lines)
	}
	if f.Lines[0].Change != "new" || f.Lines[0].Names() != "acme: dev; globex: dev" || f.Lines[1].Change != "priority P2 -> P1" {
		t.Errorf("lines = %+v", f.Lines)
	}
}

func TestFindingsTwoProductsSameID(t *testing.T) {
	fs := Findings([]Item{
		scopedItem("acme", "dev", "alpha", "CVE-1", "1", "P1", "new", "a"),
		scopedItem("acme", "dev", "beta", "CVE-1", "1", "P1", "new", "a"),
	})
	if len(fs) != 2 || fs[0].Product != "alpha" || fs[1].Product != "beta" {
		t.Errorf("findings = %+v, want two in order", fs)
	}
}

func TestFindingsNoTenants(t *testing.T) {
	items := []Item{
		{ID: "CVE-1", Product: "p", Constraint: "1", Priority: "P1", Change: "new", Action: "a"},
		{ID: "CVE-2", Product: "p", Constraint: "1", Priority: "P2", Change: "new", Action: "a"},
		{ID: "CVE-2", Product: "p", Constraint: "2", Priority: "P2", Change: "new", Action: "a"},
	}
	fs := Findings(items)
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want one per item", len(fs))
	}
	for _, f := range fs {
		if len(f.Lines) != 0 || len(f.Scopes) != 0 {
			t.Errorf("finding %s has lines or scopes: %+v", f.ID, f)
		}
	}
	if c := Count(fs); c.Findings != 3 || c.Scopes != 0 {
		t.Errorf("counts = %+v", c)
	}
}

func TestOpenFindings(t *testing.T) {
	mk := func(tenant, env, constraint, prio string) OpenItem {
		return OpenItem{ID: "CVE-1", Product: "p", Tenant: tenant, Environment: env, Scope: tenant + "/" + env, Constraint: constraint, Priority: prio, Action: "own"}
	}
	items := []OpenItem{
		mk("acme", "dev", "1", "P1"),
		mk("globex", "dev", "1", "P1"),
		mk("acme", "prod", "2", "P1"),
	}
	fs := OpenFindings(items, func(OpenItem) string { return "Still open: upgrade" })
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.Action != "Still open: upgrade" || f.Change != "" {
		t.Errorf("action = %q, change = %q", f.Action, f.Change)
	}
	if len(f.Lines) != 2 || f.Lines[0].Names() != "acme: dev; globex: dev" || f.Lines[1].Constraint != "2" {
		t.Errorf("lines = %+v", f.Lines)
	}
	if c := Count(fs); c.Scopes != 3 {
		t.Errorf("scopes = %d, want 3", c.Scopes)
	}
}

func TestCountScopesAreDistinctAcrossFindings(t *testing.T) {
	fs := Findings([]Item{
		scopedItem("acme", "dev", "p", "CVE-1", "1", "P1", "new", "a"),
		scopedItem("acme", "dev", "p", "CVE-2", "1", "P2", "new", "a"),
		scopedItem("globex", "dev", "p", "CVE-2", "1", "P2", "new", "a"),
	})
	c := Count(fs)
	if c.Findings != 2 || c.Scopes != 2 {
		t.Errorf("counts = %+v, want 2 findings in 2 scopes", c)
	}
}

func TestScopeList(t *testing.T) {
	got := ScopeList([]ScopeRef{{"acme", "prod"}, {"globex", "test"}, {"acme", "stage"}, {"acme", "prod"}})
	if want := "acme: prod, stage; globex: test"; got != want {
		t.Errorf("ScopeList = %q, want %q", got, want)
	}
	if got := ScopeList(nil); got != "" {
		t.Errorf("ScopeList(nil) = %q", got)
	}
}
