package report

import (
	"cmp"
	"slices"
	"time"
)

// MaxOldest is how many findings Weekly.Oldest holds.
const MaxOldest = 5

// Weekly is the weekly report: what is open, what was first reported and
// what was closed in the window, and what has been open the longest.
type Weekly struct {
	// The window: after From (the last report, or seven days back) up to
	// Until (the run), in the run's time zone, unlike the report's UTC times.
	From  time.Time `json:"from"`
	Until time.Time `json:"until"`
	// OpenCounts counts the open findings by priority once per environment,
	// like CurrentOpenCounts.
	OpenCounts []PriorityCount `json:"open_counts"`
	// New are the open findings first reported in the window.
	New []OpenItem `json:"new"`
	// Closed are the findings closed in the window.
	Closed []ClosedItem `json:"closed"`
	// Oldest are the MaxOldest findings open the longest among those first
	// reported before the window, every environment of each.
	Oldest []OpenItem `json:"oldest"`
}

// Reasons a finding was closed (ClosedItem.Reason).
const (
	ClosedFixed       = "fixed"
	ClosedRemoved     = "removed"
	ClosedRejected    = "rejected"
	ClosedNotRelevant = "not-relevant"
)

// ClosedReasons says why a finding was closed, in words.
var ClosedReasons = map[string]string{
	ClosedFixed:       "fixed",
	ClosedRemoved:     "removed from the stack",
	ClosedRejected:    "advisory rejected",
	ClosedNotRelevant: "no longer relevant",
}

// Days names the window by the days of its start and end, "16 – 23 Nov
// 2026", in the time zone of Until.
func (w *Weekly) Days() string {
	from, until := w.From.In(w.Until.Location()), w.Until
	switch {
	case from.Year() != until.Year():
		return from.Format("2 Jan 2006") + " – " + until.Format("2 Jan 2006")
	case from.Month() != until.Month():
		return from.Format("2 Jan") + " – " + until.Format("2 Jan 2006")
	}
	return from.Format("2") + " – " + until.Format("2 Jan 2006")
}

// DaysOpen is how long the oldest scope of one of the Oldest findings has
// been open.
func (w *Weekly) DaysOpen(product, id string) int {
	n := 0
	for _, it := range w.Oldest {
		if it.Product == product && it.ID == id {
			n = max(n, it.DaysOpen)
		}
	}
	return n
}

// ClosedItem is a finding that stopped being open, as last stored.
type ClosedItem struct {
	ID            string     `json:"id"`
	Product       string     `json:"product"`
	Tenant        string     `json:"tenant,omitempty"`
	Environment   string     `json:"environment,omitempty"`
	Scope         string     `json:"-"` // "tenant/environment" when stack.yaml has tenants (outputs name it)
	Title         string     `json:"title"`
	Priority      string     `json:"priority"`
	FirstReported time.Time  `json:"first_reported"`
	ClosedAt      time.Time  `json:"closed_at"`
	Reason        string     `json:"reason"`
	Link          string     `json:"link,omitempty"`
	Aliases       []string   `json:"aliases,omitempty"`
	Advisories    []Advisory `json:"advisories,omitempty"`
	References    []string   `json:"-"` // the finding's links, for Advisories
}

// ClosedFindings groups closed items by (product, ID) like OpenFindings; a
// line holds the scopes closed for the same reason (Change).
func ClosedFindings(items []ClosedItem) []Finding[ClosedItem] {
	return group(items, func(it ClosedItem) member {
		return member{it.Product, it.ID, "", "", it.Reason, "", it.Scope != "", ScopeRef{it.Tenant, it.Environment}}
	})
}

// weekly builds the weekly report from the report's open findings and the
// closed ones.
func (r Report) weekly(from, until time.Time, closed []ClosedItem) *Weekly {
	w := &Weekly{From: from, Until: until, OpenCounts: r.CurrentOpenCounts(), Closed: closed}
	open := slices.Clone(r.Open)
	for _, it := range r.Items() {
		open = append(open, openItemOf(it, r.GeneratedAt))
	}
	slices.SortStableFunc(open, openOrder)
	var older []OpenItem
	for _, it := range open {
		// The start is the last report's run, which listed it already.
		if !it.FirstReported.After(from) {
			older = append(older, it)
			continue
		}
		w.New = append(w.New, it)
	}
	w.Oldest = oldest(older, MaxOldest)
	return w
}

// openOrder is the order of Report.Open.
func openOrder(a, b OpenItem) int {
	return cmp.Or(
		cmp.Compare(a.Priority, b.Priority),
		boolCmp(b.KEV, a.KEV),
		cmp.Compare(b.CVSS, a.CVSS),
		cmp.Compare(a.Tenant, b.Tenant),
		cmp.Compare(a.Environment, b.Environment),
		cmp.Compare(a.Product, b.Product),
		cmp.Compare(a.ID, b.ID),
	)
}

// oldest returns every item of the n findings first reported the earliest;
// ties by priority, then product and ID.
func oldest(items []OpenItem, n int) []OpenItem {
	items = slices.Clone(items)
	slices.SortStableFunc(items, func(a, b OpenItem) int {
		return cmp.Or(a.FirstReported.Compare(b.FirstReported), cmp.Compare(rank(a.Priority), rank(b.Priority)),
			cmp.Compare(a.Product, b.Product), cmp.Compare(a.ID, b.ID))
	})
	// Keyed like the grouping, so n findings stay n entries.
	type key struct{ product, id, constraint string }
	keyOf := func(it OpenItem) key {
		k := key{it.Product, it.ID, ""}
		if it.Scope == "" {
			k.constraint = it.Constraint
		}
		return k
	}
	picked := map[key]bool{}
	for _, it := range items {
		if len(picked) == n {
			break
		}
		picked[keyOf(it)] = true
	}
	return slices.DeleteFunc(items, func(it OpenItem) bool { return !picked[keyOf(it)] })
}

// openItemOf is a finding reported in this run as an open item.
func openItemOf(it Item, now time.Time) OpenItem {
	return OpenItem{
		ID: it.ID, Product: it.Product, Tenant: it.Tenant, Environment: it.Environment, Scope: it.Scope,
		Constraint: it.Constraint, Title: it.Title, Fixed: it.Fixed, CVSS: it.CVSS, Severity: it.Severity,
		KEV: it.KEV, EPSS: it.EPSS, Match: it.Match, NoVersionData: it.NoVersionData, Priority: it.Priority,
		FirstReported: it.FirstReported, DaysOpen: int(now.Sub(it.FirstReported).Hours() / 24),
		Link: first(it.Links), Aliases: it.Aliases, Advisories: it.Advisories,
		Summary: it.Summary, Action: it.Action, Packages: it.Packages, ImageOnly: it.ImageOnly,
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
