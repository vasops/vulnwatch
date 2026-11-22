package discover

import (
	"maps"
	"slices"

	"github.com/vasops/vulnwatch/internal/catalog"
)

// Diff statuses, in report order.
const (
	StatusDrift        = "drift"          // the cluster runs a version the stack doesn't allow
	StatusNotInStack   = "not in stack"   // runs in the cluster but isn't watched
	StatusStale        = "stale"          // part of a union the cluster doesn't run (false findings)
	StatusNotInCluster = "not in cluster" // declared, not found (fine for things outside the cluster)
	StatusOK           = "ok"
)

// DiffRow compares one product between stack.yaml and the cluster.
type DiffRow struct {
	Product string
	Stack   string   // declared constraint; empty when not declared
	Cluster []string // versions found; empty when not found
	Stale   []string // declared alternatives no cluster version satisfies
	Status  string
}

// Diff compares the declared (resolved) stack with the observed versions.
func Diff(declared []catalog.Product, observed map[string][]string) []DiffRow {
	byName := map[string]catalog.Product{}
	for _, p := range declared {
		byName[p.Name] = p
	}
	names := slices.Sorted(maps.Keys(byName))
	for n := range observed {
		if _, ok := byName[n]; !ok {
			names = append(names, n)
		}
	}
	var rows []DiffRow
	for _, n := range names {
		p, inStack := byName[n]
		row := DiffRow{Product: n, Cluster: observed[n]}
		switch {
		case !inStack:
			row.Status = StatusNotInStack
		case len(row.Cluster) == 0:
			row.Stack, row.Status = p.Constraint.String(), StatusNotInCluster
		default:
			row.Stack, row.Status = p.Constraint.String(), StatusOK
			for _, v := range row.Cluster {
				if !p.Constraint.Allows(v) {
					row.Status = StatusDrift
				}
			}
			for _, alt := range p.Constraint.Alternatives() {
				if !slices.ContainsFunc(row.Cluster, alt.Allows) {
					row.Stale = append(row.Stale, alt.String())
				}
			}
			if row.Status == StatusOK && len(row.Stale) > 0 {
				row.Status = StatusStale
			}
		}
		rows = append(rows, row)
	}
	order := []string{StatusDrift, StatusNotInStack, StatusStale, StatusNotInCluster, StatusOK}
	slices.SortStableFunc(rows, func(a, b DiffRow) int {
		if d := slices.Index(order, a.Status) - slices.Index(order, b.Status); d != 0 {
			return d
		}
		if a.Product < b.Product {
			return -1
		}
		if a.Product > b.Product {
			return 1
		}
		return 0
	})
	return rows
}
