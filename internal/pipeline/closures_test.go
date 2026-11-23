package pipeline

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/state"
)

// rows is the stored findings by ID.
func rows(t *testing.T, e *env) map[string]state.Reported {
	t.Helper()
	rs, err := e.store.ListReported(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]state.Reported{}
	for _, r := range rs {
		out[r.ID] = r
	}
	return out
}

func whole(o *Options) { o.WholeStack = true }

// keycloakAt runs the whole stack with keycloak in version v.
func keycloakAt(t *testing.T, e *env, v string) func(*Options) {
	return func(o *Options) {
		stackWith(t, e, v)(o)
		o.WholeStack = true
	}
}

func without(name string) func(*Options) {
	return func(o *Options) {
		o.WholeStack = true
		o.Products = slices.DeleteFunc(slices.Clone(o.Products), func(p catalog.Product) bool { return p.Name == name })
	}
}

func TestClosures(t *testing.T) {
	tests := []struct {
		name   string
		second func(*testing.T, *env) func(*Options)
		reason string // "": still open, not closed
	}{
		{"upgraded past the fix", func(t *testing.T, e *env) func(*Options) { return keycloakAt(t, e, "26.1.4") }, state.ClosedFixed},
		{"product removed", func(*testing.T, *env) func(*Options) { return without("keycloak") }, state.ClosedRemoved},
		{"still affected", func(t *testing.T, e *env) func(*Options) { return keycloakAt(t, e, "26.1.0") }, ""},
		{"dry run", func(t *testing.T, e *env) func(*Options) {
			return func(o *Options) { keycloakAt(t, e, "26.1.4")(o); o.DryRun = true }
		}, ""},
		{"limited with --product", func(*testing.T, *env) func(*Options) {
			return func(o *Options) { without("keycloak")(o); o.WholeStack = false }
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			if _, err := e.run(t, whole); err != nil {
				t.Fatal(err)
			}
			first := e.now
			got := rows(t, e)
			if r := got["CVE-2026-1"]; !r.LastOpen.Equal(first) || !r.ClosedAt.IsZero() {
				t.Fatalf("open finding: %+v", r)
			}
			if r := got["CVE-2026-2"]; !r.LastOpen.IsZero() {
				t.Fatalf("a finding never listed as open has no last_open: %+v", r)
			}

			e.src = nil // the list comes from state only
			e.now = e.now.Add(24 * time.Hour)
			if _, err := e.run(t, tt.second(t, e)); err != nil {
				t.Fatal(err)
			}
			got = rows(t, e)
			r := got["CVE-2026-1"]
			if r.ClosedReason != tt.reason {
				t.Fatalf("reason %q, want %q: %+v", r.ClosedReason, tt.reason, r)
			}
			if tt.reason != "" && (!r.ClosedAt.Equal(e.now) || !r.LastOpen.Equal(first)) {
				t.Fatalf("closed: %+v", r)
			}
			if tt.reason == "" && !r.ClosedAt.IsZero() {
				t.Fatalf("must not close: %+v", r)
			}
			if r := got["CVE-2026-2"]; !r.ClosedAt.IsZero() {
				t.Fatalf("never open, never closed: %+v", r)
			}
		})
	}
}

// A changed finding that no longer matches the version is closed as fixed.
func TestClosedWhenTheAdvisoryChanges(t *testing.T) {
	e := setup(t)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(24 * time.Hour)
	for _, s := range e.src[:2] {
		for i := range s.(*fakeSource).fs {
			f := &s.(*fakeSource).fs[i]
			if f.Product == "keycloak" {
				f.Affected, f.Fixed, f.Modified = []finding.Range{{Introduced: "25.0.0", Fixed: "25.0.9"}}, []string{"25.0.9"}, e.now
			}
		}
	}
	rep, err := e.run(t, whole)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total() != 0 || rep.NotRelevant != 1 {
		t.Fatalf("the changed finding no longer affects us: %+v", rep.Items())
	}
	if r := rows(t, e)["CVE-2026-1"]; r.ClosedReason != state.ClosedFixed || !r.ClosedAt.Equal(e.now) {
		t.Fatalf("%+v", r)
	}
}

func TestRejectedAdvisoryIsClosed(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	u, err := e.store.UpdateCVEList(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.Put(ctx, state.CVEListEntry{ID: "CVE-2026-1", Updated: e.now, Removed: true}); err != nil {
		t.Fatal(err)
	}
	if err := u.Commit(ctx, state.CVEListMeta{}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-1"]; r.ClosedReason != state.ClosedRejected {
		t.Fatalf("%+v", r)
	}
}

// Rows stored before closures were tracked have no last_open: the first
// run after the upgrade closes nothing.
func TestNothingClosedInTheFirstRunAfterUpgrade(t *testing.T) {
	e := setup(t)
	f := e.src[0].(*fakeSource).fs[0]
	f.ID, f.Aliases = "CVE-2026-1", []string{"GHSA-kc-1"}
	stored := state.Record{Product: "keycloak", ID: f.ID, IDs: f.IDs(), Snapshot: f.Snapshot(), Detail: state.NewDetail(f, "P2", "yes", "rules", "26.x")}
	if err := e.store.Commit(context.Background(), e.now, []state.Record{stored}, nil, true); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, keycloakAt(t, e, "26.1.4")); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-1"]; !r.ClosedAt.IsZero() || !r.LastOpen.IsZero() {
		t.Fatalf("closed without ever being listed as open: %+v", r)
	}
}

func TestReopenedFindingLosesItsClosure(t *testing.T) {
	e := setup(t)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	for i, v := range []string{"26.1.4", "26.1.0"} {
		e.now = e.now.Add(24 * time.Hour)
		rep, err := e.run(t, keycloakAt(t, e, v))
		if err != nil {
			t.Fatal(err)
		}
		r := rows(t, e)["CVE-2026-1"]
		switch i {
		case 0:
			if r.ClosedReason != state.ClosedFixed || len(rep.Open) != 0 {
				t.Fatalf("closed: %+v", r)
			}
		case 1:
			if !r.ClosedAt.IsZero() || r.ClosedReason != "" || !r.LastOpen.Equal(e.now) || len(rep.Open) != 1 {
				t.Fatalf("open again: %+v open=%+v", r, rep.Open)
			}
		}
	}
}

// When the image source failed, an image-only finding stays open as the
// still-open list keeps it, and is not closed.
func TestImageOnlyNotClosedWhileTheImageSourceFails(t *testing.T) {
	e := setup(t)
	e.cfg.Sources.Trivy = config.TrivySource{Enabled: true, MinSeverity: "critical", MinSeverityInternet: "high", MinEPSS: 0.1}
	trivy := &fakeImageSource{fakeSource: fakeSource{name: finding.SourceTrivy}}
	trivy.fs = []finding.Finding{imageFinding("CVE-2026-50", "keycloak", "high", 7.5, "1.1", e.now)}
	e.src = append(e.src[:2], trivy)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-50"]; r.LastOpen.IsZero() {
		t.Fatalf("image-only finding not open: %+v", r)
	}
	trivy.fs, trivy.err = nil, errors.New("forbidden")
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-50"]; !r.ClosedAt.IsZero() || !r.LastOpen.Equal(e.now) {
		t.Fatalf("closed while Trivy failed: %+v", r)
	}
	trivy.err = nil // answers again, without the finding: the image no longer runs it
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-50"]; r.ClosedReason != state.ClosedFixed {
		t.Fatalf("%+v", r)
	}
}

// Tracking closures only adds writes: the report is the same with and
// without it.
func TestClosuresLeaveTheReportUnchanged(t *testing.T) {
	reports := map[bool][]any{}
	for _, track := range []bool{false, true} {
		e := setup(t)
		mut := func(o *Options) { o.WholeStack = track }
		for i := range 3 {
			if i == 2 {
				e.src = nil
				mut = func(o *Options) { stackWith(t, e, "26.1.4")(o); o.WholeStack = track }
			}
			rep, err := e.run(t, mut)
			if err != nil {
				t.Fatal(err)
			}
			reports[track] = append(reports[track], rep.Open, rep.OpenUnknown, rep.Counts, rep.CurrentOpenCounts())
			e.now = e.now.Add(24 * time.Hour)
		}
	}
	if !reflect.DeepEqual(reports[false], reports[true]) {
		t.Fatalf("report changed:\n%+v\n%+v", reports[false], reports[true])
	}
}

// A finding only counted ("open, cannot be tracked": a product tracked with
// "*") is open: it gets last_open and is not closed.
func TestCountedFindingIsOpen(t *testing.T) {
	e := setup(t)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	rep, err := e.run(t, keycloakAt(t, e, "*"))
	if err != nil || len(rep.Open) != 0 || rep.OpenUnknown == 0 {
		t.Fatalf("counted, not listed: %v open=%+v unknown=%d", err, rep.Open, rep.OpenUnknown)
	}
	if r := rows(t, e)["CVE-2026-1"]; !r.LastOpen.Equal(e.now) || !r.ClosedAt.IsZero() {
		t.Fatalf("%+v", r)
	}
}

func TestBootstrapTracksClosures(t *testing.T) {
	e := setup(t)
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	e.src = nil
	e.now = e.now.Add(24 * time.Hour)
	if _, err := e.run(t, func(o *Options) { keycloakAt(t, e, "26.1.4")(o); o.Bootstrap = true }); err != nil {
		t.Fatal(err)
	}
	if r := rows(t, e)["CVE-2026-1"]; r.ClosedReason != state.ClosedFixed || !r.ClosedAt.Equal(e.now) {
		t.Fatalf("%+v", r)
	}
}

// A run whose output fails writes no open, closed or weekly state.
func TestFailedOutputWritesNoClosures(t *testing.T) {
	e := setup(t)
	e.cfg.Outputs.Slack.Weekly = config.SlackWeekly{Enabled: true, Day: "monday"}
	e.now = time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC) // Sunday
	if _, err := e.run(t, whole); err != nil {
		t.Fatal(err)
	}
	first := e.now
	e.src = nil
	e.out.err = errors.New("slack down")
	for _, v := range []string{"26.1.4", "26.1.0"} { // would close; would mark open
		e.now = e.now.Add(24 * time.Hour) // Monday (weekly due), Tuesday
		rep, err := e.run(t, keycloakAt(t, e, v))
		if err == nil || (v == "26.1.4" && rep.Weekly == nil) {
			t.Fatalf("%s: the run must fail after building the weekly report: %v", v, err)
		}
		if r := rows(t, e)["CVE-2026-1"]; !r.LastOpen.Equal(first) || !r.ClosedAt.IsZero() {
			t.Fatalf("%s: state written: %+v", v, r)
		}
		if _, ok, err := e.store.LastWeekly(context.Background()); ok || err != nil {
			t.Fatalf("%s: weekly recorded: %v %v", v, ok, err)
		}
	}
}

// Only findings open in an earlier run and not closed yet go to the commit
// as closures; the rest would change nothing.
func TestCommitClosesOnlyOpenRows(t *testing.T) {
	at := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	row := func(id string, lastOpen, closedAt time.Time, aliases ...string) state.Reported {
		return state.Reported{Product: "keycloak", ID: id, LastOpen: lastOpen, ClosedAt: closedAt,
			Detail: state.Detail{Finding: finding.Finding{ID: id, Aliases: aliases}}}
	}
	stored := []state.Reported{
		row("CVE-2026-1", at, time.Time{}),                            // open last run
		row("CVE-2026-2", at.AddDate(0, 0, -9), at.AddDate(0, 0, -8)), // closed long ago
		row("CVE-2026-3", time.Time{}, time.Time{}),                   // never open
		row("CVE-2026-4", at.AddDate(0, 0, -9), at.AddDate(0, 0, -8)), // closed, but its GHSA row was open
		row("GHSA-4", at, time.Time{}),
		row("CVE-2026-5", at, time.Time{}), // open last run, open now
	}
	c := newClosures()
	for _, id := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"} {
		c.markGone("keycloak", id, nil, state.ClosedFixed)
	}
	c.markGone("keycloak", "CVE-2026-4", []string{"CVE-2026-4", "GHSA-4"}, state.ClosedNotRelevant)
	c.markGone("keycloak", "CVE-2026-5", nil, state.ClosedFixed)
	c.markOpen("keycloak", "CVE-2026-5")
	open, closed := c.commit(true, stored)
	want := []state.Closure{{Product: "keycloak", ID: "CVE-2026-1", Reason: state.ClosedFixed}, {Product: "keycloak", ID: "CVE-2026-4", Reason: state.ClosedNotRelevant}}
	if !reflect.DeepEqual(closed, want) || len(open) != 1 {
		t.Fatalf("closed %+v open %+v", closed, open)
	}
	if _, closed := c.commit(false, stored); closed != nil {
		t.Fatalf("closed without tracking: %+v", closed)
	}
}
