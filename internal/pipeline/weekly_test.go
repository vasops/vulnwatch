package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/state"
)

func TestPlanWeekly(t *testing.T) {
	cet := time.FixedZone("CET", 3600)
	monday := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	weekAgo := monday.AddDate(0, 0, -7)
	tests := []struct {
		name         string
		enabled      bool
		last         time.Time // zero: never sent
		at           time.Time
		mut          func(*Options)
		send, record bool
		from         time.Time // zero: at minus seven days
	}{
		{"disabled", false, time.Time{}, monday, nil, false, false, time.Time{}},
		{"on the weekday", true, weekAgo, monday, nil, true, true, weekAgo},
		{"first time on the weekday", true, time.Time{}, monday, nil, true, true, time.Time{}},
		{"first time waits for the weekday", true, time.Time{}, monday.AddDate(0, 0, 1), nil, false, false, time.Time{}},
		{"another day", true, monday, monday.AddDate(0, 0, 3), nil, false, false, monday},
		{"not twice on the same day", true, monday.Add(-time.Hour), monday, nil, false, false, monday.Add(-time.Hour)},
		{"catch-up covers the eight days since the last one", true, monday.AddDate(0, 0, -8), monday.AddDate(0, 0, 1), nil, true, true, monday.AddDate(0, 0, -8)},
		{"six days later", true, weekAgo, monday.AddDate(0, 0, -1), nil, false, false, weekAgo},
		{"last report older than 14 days: seven days", true, monday.AddDate(0, 0, -15), monday, nil, true, true, time.Time{}},
		{"earlier in the day than last week: from the last report", true, weekAgo.Add(7 * time.Second), monday.Add(3 * time.Second), nil, true, true, weekAgo.Add(7 * time.Second)},
		{"local time decides the day", true, time.Time{}, time.Date(2026, 11, 23, 0, 30, 0, 0, cet), nil, true, true, time.Time{}}, // Sunday 23:30 UTC
		{"local time: still Sunday", true, time.Time{}, time.Date(2026, 11, 22, 23, 30, 0, 0, cet), nil, false, false, time.Time{}},
		{"same local day, other UTC day", true, time.Date(2026, 11, 22, 23, 30, 0, 0, time.UTC), time.Date(2026, 11, 23, 6, 0, 0, 0, cet), nil, false, false, time.Date(2026, 11, 22, 23, 30, 0, 0, time.UTC)},
		{"--weekly forces, records nothing", false, monday, monday.AddDate(0, 0, 2), func(o *Options) { o.Weekly = true }, true, false, monday},
		{"--weekly on a due day records", true, weekAgo, monday, func(o *Options) { o.Weekly = true }, true, true, weekAgo},
		{"never in bootstrap", true, time.Time{}, monday, func(o *Options) { o.Bootstrap = true }, false, false, time.Time{}},
		{"--weekly not in bootstrap", true, time.Time{}, monday, func(o *Options) { o.Bootstrap, o.Weekly = true, true }, false, false, time.Time{}},
		{"not in a run limited with --product", true, time.Time{}, monday, func(o *Options) { o.WholeStack = false }, false, false, time.Time{}},
		{"--product with --weekly", true, time.Time{}, monday, func(o *Options) { o.WholeStack, o.Weekly = false, true }, true, false, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			e.cfg.Outputs.Slack.Weekly = config.SlackWeekly{Enabled: tt.enabled, Day: "monday"}
			if !tt.last.IsZero() {
				if err := e.store.CommitRun(context.Background(), tt.last, state.RunCommit{Weekly: true}); err != nil {
					t.Fatal(err)
				}
			}
			o := Options{Config: e.cfg, Store: e.store, WholeStack: true}
			if tt.mut != nil {
				tt.mut(&o)
			}
			got, err := planWeekly(context.Background(), o, tt.at)
			if err != nil || got.send != tt.send || got.record != tt.record {
				t.Fatalf("send %v record %v (%v), want %v %v", got.send, got.record, err, tt.send, tt.record)
			}
			want := tt.from
			if want.IsZero() {
				want = tt.at.AddDate(0, 0, -7)
			}
			if tt.send && !got.from.Equal(want) {
				t.Fatalf("from %v, want %v", got.from, want)
			}
		})
	}
}

func TestWeeklyReportInRun(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	e.cfg.Outputs.Slack.Weekly = config.SlackWeekly{Enabled: true, Day: "monday"}
	e.now = time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC) // Sunday
	rep, err := e.run(t, whole)
	if err != nil || rep.Weekly != nil {
		t.Fatalf("not due on Sunday: %v %+v", err, rep.Weekly)
	}

	// Monday, upgraded past the fix: the finding is closed in this run and
	// listed in the weekly report.
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	monday := e.now
	rep, err = e.run(t, keycloakAt(t, e, "26.1.4"))
	if err != nil {
		t.Fatal(err)
	}
	w := rep.Weekly
	if w == nil || !w.Until.Equal(e.now) || !w.From.Equal(e.now.AddDate(0, 0, -7)) {
		t.Fatalf("weekly: %+v", w)
	}
	if len(w.Closed) != 1 || w.Closed[0].ID != "CVE-2026-1" || w.Closed[0].Reason != state.ClosedFixed ||
		w.Closed[0].Product != "keycloak" || w.Closed[0].Title != "kc vuln" || w.Closed[0].Tenant != e.products[0].Scope.Tenant {
		t.Fatalf("closed: %+v", w.Closed)
	}
	lastWeekly := func() time.Time {
		t.Helper()
		last, _, err := e.store.LastWeekly(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return last
	}
	if !lastWeekly().Equal(monday) {
		t.Fatalf("weekly not recorded: %v", lastWeekly())
	}

	// A rerun the same day sends none.
	e.now = e.now.Add(time.Hour)
	if rep, err = e.run(t, keycloakAt(t, e, "26.1.4")); err != nil || rep.Weekly != nil {
		t.Fatalf("rerun: %v %+v", err, rep.Weekly)
	}

	// A forced preview later in the week starts at the last report, which
	// listed the closure already, and records nothing.
	e.now = e.now.AddDate(0, 0, 2)
	rep, err = e.run(t, func(o *Options) { keycloakAt(t, e, "26.1.4")(o); o.DryRun, o.Weekly = true, true })
	if err != nil || rep.Weekly == nil || !rep.Weekly.From.Equal(monday) || len(rep.Weekly.Closed) != 0 {
		t.Fatalf("forced preview: %v %+v", err, rep.Weekly)
	}

	// Forced and sent, but not due: the schedule and the next window stay.
	rep, err = e.run(t, func(o *Options) { keycloakAt(t, e, "26.1.0")(o); o.Weekly = true })
	if err != nil || rep.Weekly == nil || len(rep.Weekly.Closed) != 0 || len(rep.Open) != 1 {
		t.Fatalf("forced, open again: %v %+v", err, rep.Weekly)
	}
	if !lastWeekly().Equal(monday) {
		t.Fatalf("a forced report that was not due must not be recorded: %v", lastWeekly())
	}

	// Closed again on Thursday; the next Monday's run lists that closure
	// from the state, once.
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, keycloakAt(t, e, "26.1.4")); err != nil {
		t.Fatal(err)
	}
	thursday := e.now
	e.now = monday.AddDate(0, 0, 7).Add(-time.Second) // a little earlier in the day
	rep, err = e.run(t, keycloakAt(t, e, "26.1.4"))
	if err != nil || rep.Weekly == nil || !rep.Weekly.From.Equal(monday) {
		t.Fatalf("next Monday: %v %+v", err, rep.Weekly)
	}
	if cs := rep.Weekly.Closed; len(cs) != 1 || !cs[0].ClosedAt.Equal(thursday) {
		t.Fatalf("closed: %+v", cs)
	}
	if !lastWeekly().Equal(e.now) {
		t.Fatalf("a due report is recorded: %v", lastWeekly())
	}
}

// A run that starts a few seconds earlier in the day than last week's does
// not list again what last week's report listed.
func TestWeeklyListsAClosureOnce(t *testing.T) {
	e := setup(t)
	e.cfg.Outputs.Slack.Weekly = config.SlackWeekly{Enabled: true, Day: "monday"}
	e.now = time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC) // Sunday
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	e.now = time.Date(2026, 11, 23, 6, 0, 7, 0, time.UTC)
	rep, err := e.run(t, keycloakAt(t, e, "26.1.4"))
	if err != nil || rep.Weekly == nil || len(rep.Weekly.Closed) != 1 {
		t.Fatalf("week 1: %v %+v", err, rep.Weekly)
	}
	e.now = time.Date(2026, 11, 30, 6, 0, 3, 0, time.UTC)
	rep, err = e.run(t, keycloakAt(t, e, "26.1.4"))
	if err != nil || rep.Weekly == nil || len(rep.Weekly.Closed) != 0 || len(rep.Weekly.New) != 0 {
		t.Fatalf("week 2 lists week 1 again: %v %+v", err, rep.Weekly)
	}
}

// A report caught up after a missed week covers everything since the last
// one, more than seven days.
func TestWeeklyCatchUpCoversTheWholeGap(t *testing.T) {
	e := setup(t)
	e.cfg.Outputs.Slack.Weekly = config.SlackWeekly{Enabled: true, Day: "monday"}
	monday := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	e.now = monday
	if _, err := e.run(t, whole); err != nil { // the first report
		t.Fatal(err)
	}
	e.src = nil
	e.now = monday.Add(12 * time.Hour) // closed the same evening
	if _, err := e.run(t, keycloakAt(t, e, "26.1.4")); err != nil {
		t.Fatal(err)
	}
	e.now = monday.AddDate(0, 0, 8) // next Monday's run failed; Tuesday catches up
	rep, err := e.run(t, keycloakAt(t, e, "26.1.4"))
	if err != nil || rep.Weekly == nil || !rep.Weekly.From.Equal(monday) {
		t.Fatalf("catch-up: %v %+v", err, rep.Weekly)
	}
	if cs := rep.Weekly.Closed; len(cs) != 1 || !cs[0].ClosedAt.Equal(monday.Add(12*time.Hour)) {
		t.Fatalf("a closure eight days ago is in the catch-up: %+v", cs)
	}
}

// A closed finding keeps the tenant and environment of its product key,
// also when the environment left the stack.
func TestWeeklyClosedOfRemovedEnvironment(t *testing.T) {
	e := setup(t)
	e.src[2].(*fakeSource).err = nil
	both := scopedProducts(t, e.cfg, "tenants:\n  acme:\n    environments:\n      prod: {products: {keycloak: '26.x'}}\n      stage: {products: {keycloak: '26.x'}}\n")
	if _, err := e.run(t, func(o *Options) { o.Products, o.WholeStack = both, true }); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	prodOnly := scopedProducts(t, e.cfg, "tenants:\n  acme:\n    environments:\n      prod: {products: {keycloak: '26.x'}}\n")
	rep, err := e.run(t, func(o *Options) { o.Products, o.WholeStack, o.Weekly = prodOnly, true, true })
	if err != nil {
		t.Fatal(err)
	}
	cs := rep.Weekly.Closed
	if len(cs) != 1 || cs[0].Tenant != "acme" || cs[0].Environment != "stage" || cs[0].Product != "keycloak" ||
		cs[0].Reason != state.ClosedRemoved || cs[0].Scope != "acme/stage" {
		t.Fatalf("closed: %+v", cs)
	}
}
