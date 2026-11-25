package pipeline

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/state"
)

const (
	week = 7 * 24 * time.Hour
	// maxWindow is how far back the window reaches to the last report; an
	// older one (weekly switched off meanwhile) gives the last seven days.
	maxWindow = 2 * week
)

// weeklyPlan is whether the run sends the weekly report, whether it
// records it (it was due, not only forced), and where its window starts.
type weeklyPlan struct {
	send, record bool
	from         time.Time
}

// planWeekly decides the weekly report of a run at at, the run's time in
// the local time zone, which decides the day.
func planWeekly(ctx context.Context, o Options, at time.Time) (weeklyPlan, error) {
	if o.Bootstrap {
		return weeklyPlan{}, nil
	}
	last, sent, err := o.Store.LastWeekly(ctx)
	if err != nil {
		return weeklyPlan{}, err
	}
	p := weeklyPlan{from: at.AddDate(0, 0, -7)}
	// From the last report on, so nothing is listed in two reports when a
	// run starts a little earlier in the day than the week before.
	if sent && last.Before(at) && at.Sub(last) <= maxWindow {
		p.from = last.In(at.Location())
	}
	w := o.Config.Outputs.Slack.Weekly
	day, ok := w.Weekday()
	// A run limited to some products would report only theirs as open.
	if w.Enabled && ok && o.WholeStack {
		switch {
		case sent && midnight(last.In(at.Location())).Equal(midnight(at)):
			// sent today: a rerun does not repeat it
		case sent && at.Sub(last) > week:
			p.record = true // the weekday's report was missed
		default:
			p.record = at.Weekday() == day
		}
	}
	p.send = p.record || o.Weekly
	return p, nil
}

func midnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// weeklyInput is the weekly report's window, after from up to at, and the
// findings closed in it: those closed by earlier runs and not open again,
// and those this run closes (only when it tracks closures).
func weeklyInput(ctx context.Context, o Options, from, at time.Time, cl *closures, stored []state.Reported) (*report.Weekly, error) {
	earlier, err := o.Store.ClosedBetween(ctx, from, at)
	if err != nil {
		return nil, err
	}
	closed := slices.DeleteFunc(earlier, func(r state.Reported) bool { return cl.open[state.Key{Product: r.Product, ID: r.ID}] })
	if o.WholeStack {
		closed = append(closed, cl.closing(stored, at.UTC())...)
	}
	local := config.Scope{Tenant: config.DefaultTenant, Environment: config.DefaultEnvironment}
	if i := slices.IndexFunc(o.Products, func(p catalog.Product) bool { return !p.Scope.Remote }); i >= 0 {
		local = o.Products[i].Scope
	}
	w := &report.Weekly{From: from, Until: at}
	for _, r := range closed {
		w.Closed = append(w.Closed, closedItem(r, local))
	}
	return w, nil
}

// closedItem is a stored closed finding for the report. Its tenant and
// environment come from the product key (config.Scope.Prefix), so a
// finding of an environment no longer in the stack keeps them. A local
// key has no scope: it takes the current local stack's, or local/default
// when none is left, and a product name with two slashes would be misread.
func closedItem(r state.Reported, local config.Scope) report.ClosedItem {
	tenant, env, name := local.Tenant, local.Environment, r.Product
	if parts := strings.SplitN(r.Product, "/", 3); len(parts) == 3 {
		tenant, env, name = parts[0], parts[1], parts[2]
	}
	f := r.Detail.Finding
	it := report.ClosedItem{
		ID: r.ID, Product: name, Tenant: tenant, Environment: env, Title: f.Title, Priority: r.Detail.Priority,
		FirstReported: r.FirstReported, ClosedAt: r.ClosedAt, Reason: r.ClosedReason,
		Aliases:    slices.DeleteFunc(f.IDs(), func(a string) bool { return a == r.ID }),
		References: f.References,
	}
	if len(f.References) > 0 {
		it.Link = f.References[0]
	}
	return it
}
