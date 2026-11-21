package state

import (
	"context"
	"maps"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestCVEListIndex(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	ids := func(m map[string]time.Time) []string { return slices.Sorted(maps.Keys(m)) }
	lookup := func(since time.Time, keys ...string) []string {
		t.Helper()
		m, err := s.CVEListLookup(ctx, keys, since)
		if err != nil {
			t.Fatal(err)
		}
		return ids(m)
	}

	// The dump.
	u, err := s.UpdateCVEList(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []CVEListEntry{
		{ID: "CVE-1", Updated: day.Add(-48 * time.Hour), Keys: []string{"name:apache\thttpd", "cpe:apache:http_server"}},
		{ID: "CVE-2", Updated: day.Add(-time.Hour), Keys: []string{"name:apache\thttpd"}},
		{ID: "CVE-3", Updated: day.Add(-time.Hour), Keys: []string{"pkg:xz"}},
		{ID: "CVE-4", Updated: day, Removed: true, Keys: []string{"pkg:xz"}},
	} {
		if err := u.Put(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.Commit(ctx, CVEListMeta{Baseline: "2026-11-11", Applied: "2026-11-10"}); err != nil {
		t.Fatal(err)
	}
	if got := lookup(time.Time{}, "name:apache\thttpd", "pkg:xz"); !slices.Equal(got, []string{"CVE-1", "CVE-2", "CVE-3"}) {
		t.Fatalf("full lookup: %v", got)
	}
	if got := lookup(day.Add(-2*time.Hour), "name:apache\thttpd"); !slices.Equal(got, []string{"CVE-2"}) {
		t.Fatalf("lookup since: %v", got)
	}

	// A delta: CVE-1 changes its keys, CVE-3 is rejected, an older copy of
	// CVE-2 is ignored, CVE-5 is new.
	u, err = s.UpdateCVEList(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []CVEListEntry{
		{ID: "CVE-1", Updated: day.Add(2 * time.Hour), Keys: []string{"cpe:apache:http_server"}},
		{ID: "CVE-2", Updated: day.Add(-3 * time.Hour), Keys: []string{"pkg:other"}},
		{ID: "CVE-3", Updated: day.Add(3 * time.Hour), Removed: true},
		{ID: "CVE-5", Updated: day.Add(4 * time.Hour), Keys: []string{"pkg:xz"}},
	} {
		if err := u.Put(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := u.Commit(ctx, CVEListMeta{Applied: "2026-11-11"}); err != nil {
		t.Fatal(err)
	}
	if got := lookup(time.Time{}, "name:apache\thttpd"); !slices.Equal(got, []string{"CVE-2"}) {
		t.Fatalf("name after delta: %v", got)
	}
	if got := lookup(time.Time{}, "pkg:xz", "cpe:apache:http_server"); !slices.Equal(got, []string{"CVE-1", "CVE-5"}) {
		t.Fatalf("after delta: %v", got)
	}
	if got := lookup(time.Time{}, "pkg:other"); len(got) != 0 {
		t.Fatalf("older copy applied: %v", got)
	}
	rejected := func(s *Store) []string {
		t.Helper()
		m, err := s.CVEListRejected(ctx, []string{"CVE-1", "CVE-3", "CVE-4", "CVE-9"})
		if err != nil {
			t.Fatal(err)
		}
		return slices.Sorted(maps.Keys(m))
	}
	if got := rejected(s); !slices.Equal(got, []string{"CVE-3", "CVE-4"}) {
		t.Fatalf("rejected: %v", got)
	}
	m, err := s.CVEListMeta(ctx)
	if err != nil || m != (CVEListMeta{Baseline: "2026-11-11", Applied: "2026-11-11"}) {
		t.Fatalf("meta: %+v %v", m, err)
	}

	// A failed update leaves the index as it was.
	u, err = s.UpdateCVEList(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	u.Rollback()
	if got := lookup(time.Time{}, "pkg:xz"); !slices.Equal(got, []string{"CVE-5"}) {
		t.Fatalf("after rollback: %v", got)
	}
	s.Close()

	ro, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if !ro.ReadOnly() {
		t.Fatal("read-only store")
	}
	if _, err := ro.UpdateCVEList(ctx, false); err == nil {
		t.Fatal("update on a read-only store")
	}
	if got, err := ro.CVEListLookup(ctx, []string{"pkg:xz"}, time.Time{}); err != nil || len(got) != 1 {
		t.Fatalf("read-only lookup: %v %v", got, err)
	}
	if got := rejected(ro); !slices.Equal(got, []string{"CVE-3", "CVE-4"}) {
		t.Fatalf("read-only rejected: %v", got)
	}
}

func TestCVEListRejectedMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")

	// An index from before rejected records were kept.
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TABLE cvelist_record`,
		`CREATE TABLE cvelist_record (id TEXT PRIMARY KEY, updated TEXT NOT NULL) WITHOUT ROWID`,
		`INSERT INTO meta (key, value) VALUES ('cvelist_baseline', '2026-11-01'), ('cvelist_applied', '2026-11-10')`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	ro, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ro.CVEListRejected(ctx, []string{"CVE-1"}); err != nil || len(got) != 0 {
		t.Fatalf("read-only old index: %v %v", got, err)
	}
	ro.Close()

	s, err = Open(ctx, path, false) // migrates
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if m, err := s.CVEListMeta(ctx); err != nil || m.Baseline != "" {
		t.Fatalf("the old index must be rebuilt: %+v %v", m, err)
	}
	if got, err := s.CVEListRejected(ctx, []string{"CVE-1"}); err != nil || len(got) != 0 {
		t.Fatalf("migrated: %v %v", got, err)
	}
}
