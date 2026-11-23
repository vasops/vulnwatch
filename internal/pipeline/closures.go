package pipeline

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/state"
)

// closures is what a run learns about its stored findings: which it lists
// as open, and which left the open list and why.
type closures struct {
	open map[state.Key]bool
	gone []gone
}

// gone is a finding that is not open in this run.
type gone struct {
	key state.Key // where it is stored after the run's commit
	// ids are the finding's IDs when the run stores it again: the commit
	// folds every row stored under one of them into key. Empty: key only.
	ids    []string
	reason string
}

func newClosures() *closures { return &closures{open: map[state.Key]bool{}} }

func (c *closures) markOpen(product, id string) { c.open[state.Key{Product: product, ID: id}] = true }

// markGone records a finding the run does not list as open; ids are its IDs
// when the run stores it again (see gone).
func (c *closures) markGone(product, id string, ids []string, reason string) {
	c.gone = append(c.gone, gone{key: state.Key{Product: product, ID: id}, ids: ids, reason: reason})
}

// dropReason is why openItem dropped a finding.
func dropReason(outcome int) string {
	if outcome == openNotAffected {
		return state.ClosedFixed
	}
	return state.ClosedNotRelevant
}

// commit is the run's open and closed findings for the state. Without
// track nothing is closed: in a run limited to some products the others
// would look removed. stored is the state before the run.
func (c *closures) commit(track bool, stored []state.Reported) ([]state.Key, []state.Closure) {
	open := slices.SortedFunc(maps.Keys(c.open), func(a, b state.Key) int {
		return cmp.Or(strings.Compare(a.Product, b.Product), strings.Compare(a.ID, b.ID))
	})
	if !track {
		return open, nil
	}
	var closed []state.Closure
	for _, r := range c.closing(stored, time.Time{}) {
		closed = append(closed, state.Closure{Product: r.Product, ID: r.ID, Reason: r.ClosedReason})
	}
	return open, closed
}

// closing returns the findings this run closes, as stored after the commit
// with closed_at at: those whose rows were open most recently in a run
// before and are not closed yet. Only these go to the commit: a stored
// finding not open for long is left alone, not updated every run.
func (c *closures) closing(stored []state.Reported, at time.Time) []state.Reported {
	byID := map[state.Key][]int{} // by product and any of a row's IDs
	for i, r := range stored {
		for _, id := range append([]string{r.ID}, r.Detail.Finding.IDs()...) {
			k := state.Key{Product: r.Product, ID: id}
			if !slices.Contains(byID[k], i) {
				byID[k] = append(byID[k], i)
			}
		}
	}
	var out []state.Reported
	seen := map[state.Key]bool{}
	for _, g := range c.gone {
		if c.open[g.key] || seen[g.key] {
			continue
		}
		// The state after the commit is that of the merged row open most
		// recently, as state.CommitRun decides it.
		var latest *state.Reported
		for _, id := range append([]string{g.key.ID}, g.ids...) {
			for _, i := range byID[state.Key{Product: g.key.Product, ID: id}] {
				r := stored[i]
				if len(g.ids) == 0 && r.ID != g.key.ID {
					continue // not stored again: no other row is merged
				}
				if !r.LastOpen.IsZero() && (latest == nil || r.LastOpen.After(latest.LastOpen)) {
					latest = &r
				}
			}
		}
		if latest == nil || !latest.ClosedAt.IsZero() {
			continue
		}
		seen[g.key] = true
		r := *latest
		r.ID, r.ClosedAt, r.ClosedReason = g.key.ID, at, g.reason
		out = append(out, r)
	}
	return out
}
