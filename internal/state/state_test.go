package state

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/finding"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LastSuccess(ctx); err != nil || ok {
		t.Fatalf("fresh db: ok=%v err=%v", ok, err)
	}
	at := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	snap := finding.Snapshot{Severity: "high", Match: "unknown"}
	err = s.Commit(ctx, at, []Record{{Product: "openbao", ID: "GHSA-1", IDs: []string{"GHSA-1"}, Snapshot: snap}}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	last, ok, err := s.LastSuccess(ctx)
	if err != nil || !ok || !last.Equal(at) {
		t.Fatalf("last success %v %v %v", last, ok, err)
	}
	p, err := s.Lookup(ctx, "openbao", []string{"CVE-2026-1", "GHSA-1"})
	if err != nil || p == nil || p.ID != "GHSA-1" || p.Snapshot.Severity != "high" {
		t.Fatalf("lookup: %+v %v", p, err)
	}
	if p, _ := s.Lookup(ctx, "other", []string{"GHSA-1"}); p != nil {
		t.Fatal("lookup must be per product")
	}

	// The GHSA later gets a CVE: canonical ID moves, history follows.
	snap.KEV = true
	err = s.Commit(ctx, at.Add(time.Hour), []Record{{Product: "openbao", ID: "CVE-2026-1", IDs: []string{"CVE-2026-1", "GHSA-1"}, PriorID: "GHSA-1", Snapshot: snap}}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	p, err = s.Lookup(ctx, "openbao", []string{"GHSA-1"})
	if err != nil || p == nil || p.ID != "CVE-2026-1" || !p.Snapshot.KEV {
		t.Fatalf("after id move: %+v %v", p, err)
	}
	if last, _, _ := s.LastSuccess(ctx); !last.Equal(at) {
		t.Fatal("last success must not move when setLastSuccess=false")
	}
	if err := s.PutCache(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	s.Close()

	ro, err := Open(ctx, path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if p, _ := ro.Lookup(ctx, "openbao", []string{"CVE-2026-1"}); p == nil {
		t.Fatal("read-only store must read existing data")
	}
	if b, _, ok, _ := ro.GetCache(ctx, "k"); !ok || string(b) != "v" {
		t.Fatal("cache read")
	}
	if err := ro.Commit(ctx, at, nil, nil, true); err == nil {
		t.Fatal("read-only commit must fail")
	}
	if err := ro.PutCache(ctx, "k", []byte("x")); err != nil {
		t.Fatal("read-only PutCache should be a no-op")
	}
}

func TestReadOnlyMissingFile(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "missing.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.LastSuccess(ctx); err != nil || ok {
		t.Fatal(ok, err)
	}
	if p, err := s.Lookup(ctx, "x", []string{"y"}); err != nil || p != nil {
		t.Fatal(p, err)
	}
}

func TestListReportedAndMigration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// A DB from before details were stored: no detail column, one row.
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TABLE reported`,
		`CREATE TABLE reported (product TEXT NOT NULL, id TEXT NOT NULL, snapshot TEXT NOT NULL, hash TEXT NOT NULL,
			first_reported TEXT NOT NULL, last_reported TEXT NOT NULL, PRIMARY KEY (product, id))`,
		`INSERT INTO reported VALUES ('vault', 'CVE-OLD', '{}', 'h', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')`,
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
	if rs, err := ro.ListReported(ctx); err != nil || len(rs) != 0 {
		t.Fatalf("read-only old db: %v %v", rs, err)
	}
	ro.Close()

	s, err = Open(ctx, path, false) // migrates
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	f := finding.Finding{
		ID: "CVE-NEW", Product: "vault", Title: "t", Description: "long text",
		Affected:   []finding.Range{{Introduced: "1.0.0", Fixed: "2.0.5"}},
		References: []string{"a", "b", "c", "d"},
	}
	err = s.Commit(ctx, at, []Record{{Product: "vault", ID: "CVE-NEW", IDs: []string{"CVE-NEW"},
		Detail: NewDetail(f, "P2", "yes", "llm", "1.x")}},
		[]Baseline{{Product: "vault", Constraint: "1.x", Fingerprint: "fp1"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Lookup(ctx, "vault", []string{"CVE-NEW"})
	if err != nil || p == nil || p.Detail == nil || p.Detail.Method != "llm" || !p.FirstReported.Equal(at) {
		t.Fatalf("lookup with detail: %+v %v", p, err)
	}
	bs, err := s.Baselines(ctx)
	if err != nil || bs["vault"].Fingerprint != "fp1" || bs["vault"].Constraint != "1.x" || !bs["vault"].CheckedAt.Equal(at) {
		t.Fatalf("baselines: %+v %v", bs, err)
	}
	rs, err := s.ListReported(ctx)
	if err != nil || len(rs) != 1 {
		t.Fatalf("old rows without detail are skipped: %+v %v", rs, err)
	}
	r := rs[0]
	if r.ID != "CVE-NEW" || !r.FirstReported.Equal(at) || r.Detail.Priority != "P2" || r.Detail.Method != "llm" ||
		len(r.Detail.Finding.Affected) != 1 || r.Detail.Finding.Description != "" || len(r.Detail.Finding.References) != 3 {
		t.Fatalf("detail round trip: %+v", r)
	}
}

func TestPruneBaselines(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	at := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	if err := s.Commit(ctx, at, nil, []Baseline{{Product: "vault"}, {Product: "keycloak"}, {Product: "acme/vault"}}, false); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		keep      []string
		gone      string
		remaining int
	}{
		{[]string{"vault", "keycloak", "acme/vault"}, "", 3},
		{[]string{"keycloak", "acme/vault", "new"}, "vault", 2},
		{nil, "acme/vault keycloak", 0},
	}
	for _, tt := range tests {
		gone, err := s.PruneBaselines(ctx, tt.keep)
		if err != nil || strings.Join(gone, " ") != tt.gone {
			t.Fatalf("keep %v: gone %v %v", tt.keep, gone, err)
		}
		if bs, _ := s.Baselines(ctx); len(bs) != tt.remaining {
			t.Fatalf("keep %v: remaining %v", tt.keep, bs)
		}
	}
}

func TestCommitCollapsesLinkedRows(t *testing.T) {
	ctx := context.Background()
	day := func(d int) time.Time { return time.Date(2026, 10, d, 6, 0, 0, 0, time.UTC) }
	// GHSA-1 reported on day 1, CVE-1 on day 2 as separate findings; on day 3
	// the sources link them.
	tests := []struct {
		name  string
		merge Record
	}{
		{"prior from Lookup is the CVE", Record{Product: "p", ID: "CVE-1", IDs: []string{"CVE-1", "GHSA-1"}, PriorID: "CVE-1"}},
		{"prior is the GHSA", Record{Product: "p", ID: "CVE-1", IDs: []string{"CVE-1", "GHSA-1"}, PriorID: "GHSA-1"}},
		{"no prior", Record{Product: "p", ID: "CVE-1", IDs: []string{"CVE-1", "GHSA-1"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for i, id := range []string{"GHSA-1", "CVE-1"} {
				if err := s.Commit(ctx, day(i+1), []Record{{Product: "p", ID: id, IDs: []string{id}}}, nil, false); err != nil {
					t.Fatal(err)
				}
			}
			if err := s.Commit(ctx, day(3), []Record{tt.merge}, nil, false); err != nil {
				t.Fatal(err)
			}
			rs, err := s.ListReported(ctx)
			if err != nil || len(rs) != 1 || rs[0].ID != "CVE-1" || !rs[0].FirstReported.Equal(day(1)) {
				t.Fatalf("one row with the earliest first_reported: %+v %v", rs, err)
			}
			for _, id := range []string{"GHSA-1", "CVE-1"} {
				if p, err := s.Lookup(ctx, "p", []string{id}); err != nil || p == nil || p.ID != "CVE-1" {
					t.Fatalf("lookup %s: %+v %v", id, p, err)
				}
			}
		})
	}
}

func TestSchemaVersion(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	version := func(s *Store) int {
		t.Helper()
		var v int
		if err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// A DB from before versioning (0) is current once migrated.
	s, err := Open(ctx, path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA user_version = 0`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if s, err = Open(ctx, path, false); err != nil || version(s) != schemaVersion {
		t.Fatalf("unversioned DB: %v", err)
	}

	// A newer vulnwatch's DB is refused, read-only too.
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	want := fmt.Sprintf("state DB was written by a newer vulnwatch (schema %d > %d); upgrade or use a fresh DB", schemaVersion+1, schemaVersion)
	for _, ro := range []bool{false, true} {
		if _, err := Open(ctx, path, ro); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("read-only=%v: %v", ro, err)
		}
	}
}

func TestNewsSeen(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if seen, err := s.NewsSeen(ctx, "rhsb"); err != nil || len(seen) != 0 {
		t.Fatalf("fresh: %v %v", seen, err)
	}
	at := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if err := s.MarkNewsSeen(ctx, "rhsb", []string{"RHSB-2026-017", "RHSB-2026-018"}, at); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkNewsSeen(ctx, "rhsb", []string{"RHSB-2026-018"}, at); err != nil { // again: no error
		t.Fatal(err)
	}
	seen, err := s.NewsSeen(ctx, "rhsb")
	if err != nil || len(seen) != 2 || !seen["RHSB-2026-018"] {
		t.Fatalf("seen: %v %v", seen, err)
	}
	if other, err := s.NewsSeen(ctx, "cisa"); err != nil || len(other) != 0 {
		t.Fatalf("feeds are separate: %v %v", other, err)
	}
}
