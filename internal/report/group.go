package report

import (
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/triage"
)

// ScopeRef names one tenant environment.
type ScopeRef struct{ Tenant, Environment string }

// Line is the scopes of one finding that share a constraint, a priority and
// a change. Priority is part of the key so a lower-priority marker is
// never ambiguous.
type Line struct {
	Constraint string
	Priority   string
	Change     string // equals Finding.Change when that is set
	Scopes     []ScopeRef
}

// Names is the line's scopes as plain text ("acme: dev; globex: test").
func (l Line) Names() string { return ScopeList(l.Scopes) }

// Finding is one advisory for one product, seen in one or more scopes.
type Finding[T any] struct {
	Product string
	ID      string
	// Priority is the highest among the scopes.
	Priority string
	// Representative is the item of the highest-priority scope, the first
	// among equals.
	Representative T
	// Action is the action most scopes share (see commonAction).
	Action string
	// Change is the change every scope shares; empty when they differ.
	Change string
	// Lines are in order of first appearance; none without a scope.
	Lines []Line
	// Scopes are distinct, in order of first appearance.
	Scopes []ScopeRef
}

// Findings groups items by (product, ID) in order of first appearance. An
// item without a scope is keyed by its constraint too: with no lines, a
// merge would lose the constraint.
func Findings(items []Item) []Finding[Item] {
	return group(items, func(it Item) member {
		return member{it.Product, it.ID, it.Priority, it.Constraint, it.Change, it.Action, it.Scope != "", ScopeRef{it.Tenant, it.Environment}}
	})
}

// OpenFindings groups open items the same way; they have no change.
func OpenFindings(items []OpenItem, action func(OpenItem) string) []Finding[OpenItem] {
	return group(items, func(it OpenItem) member {
		return member{it.Product, it.ID, it.Priority, it.Constraint, "", action(it), it.Scope != "", ScopeRef{it.Tenant, it.Environment}}
	})
}

// Counts are the finding and environment totals of a list of findings.
type Counts struct {
	Findings int
	// Scopes are distinct across the findings.
	Scopes int
	// ByPriority counts findings by their highest priority, in
	// triage.Priorities order with zeros kept, like Report.Counts.
	ByPriority []PriorityCount
}

// Count totals findings as grouped: findings grouped from P1 items only
// count the environments where they are P1.
func Count[T any](fs []Finding[T]) Counts {
	c := Counts{Findings: len(fs)}
	var seen []ScopeRef
	for _, f := range fs {
		for _, s := range f.Scopes {
			if !slices.Contains(seen, s) {
				seen = append(seen, s)
			}
		}
	}
	c.Scopes = len(seen)
	for _, p := range triage.Priorities {
		n := 0
		for _, f := range fs {
			if f.Priority == p {
				n++
			}
		}
		c.ByPriority = append(c.ByPriority, PriorityCount{p, n})
	}
	return c
}

// ScopeList names tenant environments compactly, tenants in order of
// appearance: "acme: prod, stage; beta: prod". Plain text, not escaped.
func ScopeList(scopes []ScopeRef) string {
	var tenants []string
	envs := map[string][]string{}
	for _, s := range scopes {
		if _, ok := envs[s.Tenant]; !ok {
			tenants = append(tenants, s.Tenant)
		}
		if !slices.Contains(envs[s.Tenant], s.Environment) {
			envs[s.Tenant] = append(envs[s.Tenant], s.Environment)
		}
	}
	parts := make([]string, len(tenants))
	for i, t := range tenants {
		parts[i] = t + ": " + strings.Join(envs[t], ", ")
	}
	return strings.Join(parts, "; ")
}

// member is what grouping reads from an Item or OpenItem.
type member struct {
	product, id, priority, constraint, change, action string
	scoped                                            bool
	scope                                             ScopeRef
}

// rank puts P1 first and an unknown priority last; a string compare would
// rank "" above P1.
func rank(p string) int {
	if i := slices.Index(triage.Priorities, p); i >= 0 {
		return i
	}
	return len(triage.Priorities)
}

func group[T any](items []T, view func(T) member) []Finding[T] {
	type key struct{ product, id, constraint string }
	type acc struct {
		f       Finding[T]
		rep     member
		members []member
	}
	idx := map[key]*acc{}
	var order []*acc
	for _, it := range items {
		m := view(it)
		k := key{m.product, m.id, ""}
		if !m.scoped {
			k.constraint = m.constraint
		}
		a := idx[k]
		if a == nil {
			a = &acc{f: Finding[T]{Product: m.product, ID: m.id, Priority: m.priority, Representative: it}, rep: m}
			idx[k] = a
			order = append(order, a)
		} else if rank(m.priority) < rank(a.rep.priority) {
			a.f.Priority, a.f.Representative, a.rep = m.priority, it, m
		}
		a.members = append(a.members, m)
	}
	out := make([]Finding[T], len(order))
	for i, a := range order {
		a.f.Action = commonAction(a.members, a.rep.action)
		a.f.Change = sharedChange(a.members)
		for _, m := range a.members {
			if !m.scoped {
				continue
			}
			if !slices.Contains(a.f.Scopes, m.scope) {
				a.f.Scopes = append(a.f.Scopes, m.scope)
			}
			a.f.Lines = addToLine(a.f.Lines, m)
		}
		out[i] = a.f
	}
	return out
}

// commonAction is the action most members share, ignoring empty ones. On a
// tie the representative's wins if it is tied, else the first tied one.
func commonAction(ms []member, repAction string) string {
	var actions []string
	n := map[string]int{}
	for _, m := range ms {
		if m.action == "" {
			continue
		}
		if n[m.action] == 0 {
			actions = append(actions, m.action)
		}
		n[m.action]++
	}
	best, bestN := "", 0
	for _, a := range actions {
		if n[a] > bestN {
			best, bestN = a, n[a]
		}
	}
	if repAction != "" && n[repAction] == bestN {
		return repAction
	}
	return best
}

// sharedChange is the change all members have, or "" when they differ.
func sharedChange(ms []member) string {
	for _, m := range ms[1:] {
		if m.change != ms[0].change {
			return ""
		}
	}
	return ms[0].change
}

// addToLine puts the member on the line with its constraint, priority and
// change, or opens one. A shared change cannot split a line.
func addToLine(lines []Line, m member) []Line {
	for i := range lines {
		l := &lines[i]
		if l.Constraint == m.constraint && l.Priority == m.priority && l.Change == m.change {
			if !slices.Contains(l.Scopes, m.scope) {
				l.Scopes = append(l.Scopes, m.scope)
			}
			return lines
		}
	}
	return append(lines, Line{Constraint: m.constraint, Priority: m.priority, Change: m.change, Scopes: []ScopeRef{m.scope}})
}
