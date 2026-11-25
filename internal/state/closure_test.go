package state

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/finding"
)

func TestClosureMigrationKeepsData(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.db")
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	// A schema 1 DB: reported without the closure columns, one row.
	for _, q := range []string{
		`DROP TABLE reported`,
		`CREATE TABLE reported (product TEXT NOT NULL, id TEXT NOT NULL, snapshot TEXT NOT NULL, hash TEXT NOT NULL,
			first_reported TEXT NOT NULL, last_reported TEXT NOT NULL, detail TEXT, PRIMARY KEY (product, id))`,
		`INSERT INTO reported VALUES ('acme/prod/keycloak', 'CVE-2026-11111', '{}', 'h', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '{"priority":"P2"}')`,
		`PRAGMA user_version = 1`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	// Read-only (dry run): not migrated, the closure columns are missing.
	ro, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ro.ListReported(ctx)
	if err != nil || len(rs) != 1 || !rs[0].LastOpen.IsZero() || !rs[0].ClosedAt.IsZero() {
		t.Fatalf("read-only v1: %+v %v", rs, err)
	}
	if cs, err := ro.ClosedBetween(ctx, time.Time{}, time.Now()); err != nil || cs != nil {
		t.Fatalf("read-only v1 closed: %+v %v", cs, err)
	}
	if _, ok, err := ro.LastWeekly(ctx); ok || err != nil {
		t.Fatalf("read-only v1 weekly: %v %v", ok, err)
	}
	if ok, _ := hasColumn(ctx, ro.db, "reported", "last_open"); ok {
		t.Fatal("a read-only state must not be migrated")
	}
	ro.Close()

	s, err = Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err = s.ListReported(ctx)
	if err != nil || len(rs) != 1 || rs[0].Detail.Priority != "P2" || rs[0].ID != "CVE-2026-11111" || !rs[0].LastOpen.IsZero() {
		t.Fatalf("migrated: %+v %v", rs, err)
	}
	var v int
	if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil || v != schemaVersion {
		t.Fatalf("version %d %v", v, err)
	}
}

func TestClosures(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	day := func(d int) time.Time { return time.Date(2026, 11, d, 6, 0, 0, 0, time.UTC) }
	const product = "acme/prod/keycloak"
	var (
		recs []Record
		open []Key
	)
	for _, id := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5"} {
		recs = append(recs, Record{Product: product, ID: id, IDs: []string{id}, Detail: Detail{Priority: "P2", Finding: finding.Finding{ID: id, Title: "t " + id}}})
		if id != "CVE-2026-5" { // never listed as open
			open = append(open, Key{product, id})
		}
	}
	if err := s.CommitRun(ctx, day(10), RunCommit{Records: recs, Open: open}); err != nil {
		t.Fatal(err)
	}
	byID := func() map[string]Reported {
		t.Helper()
		rs, err := s.ListReported(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Reported{}
		for _, r := range rs {
			out[r.ID] = r
		}
		return out
	}
	if r := byID()["CVE-2026-1"]; !r.LastOpen.Equal(day(10)) || !r.ClosedAt.IsZero() {
		t.Fatalf("last_open: %+v", r)
	}

	// Day 11: four leave the open list, each for another reason.
	closed := []Closure{
		{product, "CVE-2026-1", ClosedFixed},
		{product, "CVE-2026-2", ClosedRemoved},
		{product, "CVE-2026-3", ClosedRejected},
		{product, "CVE-2026-4", ClosedNotRelevant},
		{product, "CVE-2026-5", ClosedFixed},
	}
	if err := s.CommitRun(ctx, day(11), RunCommit{Closed: closed}); err != nil {
		t.Fatal(err)
	}
	got := byID()
	for _, c := range closed[:4] {
		if r := got[c.ID]; !r.ClosedAt.Equal(day(11)) || r.ClosedReason != c.Reason || !r.LastOpen.Equal(day(10)) {
			t.Fatalf("%s: %+v", c.ID, r)
		}
	}
	if r := got["CVE-2026-5"]; !r.ClosedAt.IsZero() || r.ClosedReason != "" {
		t.Fatalf("never open, never closed: %+v", r)
	}

	// Day 12: closing again keeps the first closure; CVE-2026-1 is open again.
	if err := s.CommitRun(ctx, day(12), RunCommit{Closed: closed[1:2], Open: []Key{{product, "CVE-2026-1"}}}); err != nil {
		t.Fatal(err)
	}
	got = byID()
	if r := got["CVE-2026-2"]; !r.ClosedAt.Equal(day(11)) {
		t.Fatalf("closed twice: %+v", r)
	}
	if r := got["CVE-2026-1"]; !r.ClosedAt.IsZero() || r.ClosedReason != "" || !r.LastOpen.Equal(day(12)) {
		t.Fatalf("reopened: %+v", r)
	}

	tests := []struct {
		name        string
		from, until time.Time
		want        string
	}{
		{"closure at the end of the range", day(10), day(11), "CVE-2026-2 CVE-2026-3 CVE-2026-4"},
		{"closure at the start of the range", day(11), day(12), ""},
		{"wide range, reopened one left out", day(4), day(12), "CVE-2026-2 CVE-2026-3 CVE-2026-4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs, err := s.ClosedBetween(ctx, tt.from, tt.until)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, c := range cs {
				ids = append(ids, c.ID)
				if c.Detail.Finding.Title != "t "+c.ID || c.Detail.Priority != "P2" || !c.FirstReported.Equal(day(10)) {
					t.Fatalf("detail: %+v", c)
				}
			}
			if strings.Join(ids, " ") != tt.want {
				t.Fatalf("got %v", ids)
			}
		})
	}
}

// When the sources link a GHSA and a CVE, the merged row is as open or
// closed as the row of the two that was open most recently.
func TestCollapseKeepsOpenState(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 6, 0, 0, 0, time.UTC) }
	rec := func(id string) Record {
		return Record{Product: "p", ID: id, IDs: []string{id}, Detail: Detail{Priority: "P2"}}
	}
	merged := Record{Product: "p", ID: "CVE-2026-1", IDs: []string{"CVE-2026-1", "GHSA-1"}, PriorID: "GHSA-1", Detail: Detail{Priority: "P2"}}
	type step struct {
		day int
		c   RunCommit
	}
	tests := []struct {
		name       string
		steps      []step
		closedAt   int // 0: open
		reason     string
		lastOpen   int
		inLastWeek bool // returned by ClosedBetween(day 14, day 21)
	}{
		{"closed GHSA folded in while not open: closure kept", []step{
			{1, RunCommit{Records: []Record{rec("GHSA-1")}, Open: []Key{{"p", "GHSA-1"}}}},
			{2, RunCommit{Closed: []Closure{{"p", "GHSA-1", ClosedRemoved}}}},
			{20, RunCommit{Records: []Record{merged}, Closed: []Closure{{"p", "CVE-2026-1", ClosedFixed}}}},
		}, 2, ClosedRemoved, 1, false},
		{"canonical row closed long ago, folded row open yesterday: closed now", []step{
			{1, RunCommit{Records: []Record{rec("CVE-2026-1")}, Open: []Key{{"p", "CVE-2026-1"}}}},
			{2, RunCommit{Closed: []Closure{{"p", "CVE-2026-1", ClosedRemoved}}}},
			{19, RunCommit{Records: []Record{rec("GHSA-1")}, Open: []Key{{"p", "GHSA-1"}}}},
			{20, RunCommit{Records: []Record{merged}, Closed: []Closure{{"p", "CVE-2026-1", ClosedFixed}}}},
		}, 20, ClosedFixed, 19, true},
		{"folded row open, finding open now: no closure", []step{
			{1, RunCommit{Records: []Record{rec("CVE-2026-1")}, Open: []Key{{"p", "CVE-2026-1"}}}},
			{2, RunCommit{Closed: []Closure{{"p", "CVE-2026-1", ClosedRemoved}}}},
			{19, RunCommit{Records: []Record{rec("GHSA-1")}, Open: []Key{{"p", "GHSA-1"}}}},
			{20, RunCommit{Records: []Record{merged}, Open: []Key{{"p", "CVE-2026-1"}}}},
		}, 0, "", 20, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for _, st := range tt.steps {
				if err := s.CommitRun(ctx, day(st.day), st.c); err != nil {
					t.Fatal(err)
				}
			}
			rs, err := s.ListReported(ctx)
			if err != nil || len(rs) != 1 {
				t.Fatalf("one merged row: %+v %v", rs, err)
			}
			r := rs[0]
			wantClosed := time.Time{}
			if tt.closedAt > 0 {
				wantClosed = day(tt.closedAt)
			}
			if !r.ClosedAt.Equal(wantClosed) || r.ClosedReason != tt.reason || !r.LastOpen.Equal(day(tt.lastOpen)) {
				t.Fatalf("%+v", r)
			}
			cs, err := s.ClosedBetween(ctx, day(14), day(21))
			if err != nil || (len(cs) == 1) != tt.inLastWeek {
				t.Fatalf("closed between day 14 and 21: %+v %v", cs, err)
			}
		})
	}
}

func TestLastWeekly(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC)
	if err := s.CommitRun(ctx, at, RunCommit{LastSuccess: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LastWeekly(ctx); ok || err != nil {
		t.Fatalf("no weekly yet: %v %v", ok, err)
	}
	if err := s.CommitRun(ctx, at, RunCommit{Weekly: true}); err != nil {
		t.Fatal(err)
	}
	if last, ok, err := s.LastWeekly(ctx); !ok || err != nil || !last.Equal(at) {
		t.Fatalf("%v %v %v", last, ok, err)
	}
}
