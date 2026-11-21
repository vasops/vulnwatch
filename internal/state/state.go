// Package state persists what has been reported, the last successful run,
// a small HTTP cache and the cvelist match index in SQLite (pure Go driver,
// CGO-free).
package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vasops/vulnwatch/internal/finding"
)

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reported (
	product        TEXT NOT NULL,
	id             TEXT NOT NULL,
	snapshot       TEXT NOT NULL,
	hash           TEXT NOT NULL,
	first_reported TEXT NOT NULL,
	last_reported  TEXT NOT NULL,
	detail         TEXT,
	PRIMARY KEY (product, id)
);
CREATE TABLE IF NOT EXISTS reported_alias (
	product TEXT NOT NULL,
	alias   TEXT NOT NULL,
	id      TEXT NOT NULL,
	PRIMARY KEY (product, alias)
);
CREATE TABLE IF NOT EXISTS baseline (
	product     TEXT PRIMARY KEY,
	constraint_ TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	checked_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
	key        TEXT PRIMARY KEY,
	fetched_at TEXT NOT NULL,
	body       BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS cvelist_record (
	id       TEXT PRIMARY KEY,
	updated  TEXT NOT NULL,
	rejected INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS cvelist_key (
	key TEXT NOT NULL,
	id  TEXT NOT NULL,
	PRIMARY KEY (key, id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS cvelist_key_id ON cvelist_key (id);
CREATE TABLE IF NOT EXISTS news_seen (
	feed    TEXT NOT NULL,
	id      TEXT NOT NULL,
	seen_at TEXT NOT NULL,
	PRIMARY KEY (feed, id)
) WITHOUT ROWID;
`

// schemaVersion is the state DB layout this binary writes, kept in PRAGMA
// user_version. Bump it with every schema change. A DB from before
// versioning (0) is current once migrated; a newer one is refused, as this
// binary would misread or damage it.
const schemaVersion = 1

const (
	keyLastSuccess  = "last_success"
	keySourceWindow = "source_window:" // + source name: where a failed source asks again from
)

// Store is the state database. A read-only store never writes; when the
// file does not exist yet it behaves like an empty database.
type Store struct {
	db       *sql.DB
	readOnly bool
}

// Open opens (and migrates) the state DB. With readOnly (dry runs), the file
// is opened read-only, or an empty in-memory DB is used if it does not exist.
func Open(ctx context.Context, path string, readOnly bool) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	migrate := true
	if readOnly {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			dsn = "file::memory:"
		} else {
			dsn = "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)"
			migrate = false
		}
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite: one writer; also keeps :memory: a single DB
	if err := checkVersion(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("open state db %s: %w", path, err)
	}
	if migrate {
		if err := migrateDB(ctx, db); err != nil {
			db.Close()
			return nil, fmt.Errorf("migrate state db %s: %w", path, err)
		}
	}
	return &Store{db: db, readOnly: readOnly}, nil
}

// checkVersion refuses a DB written by a newer vulnwatch.
func checkVersion(ctx context.Context, db *sql.DB) error {
	var v int
	if err := db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("state DB was written by a newer vulnwatch (schema %d > %d); upgrade or use a fresh DB", v, schemaVersion)
	}
	return nil
}

// migrateDB creates the schema, adds columns introduced after the first
// release to existing databases and records the schema version.
func migrateDB(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return err
	}
	for _, m := range []struct {
		table, column string
		stmts         []string
	}{
		{"reported", "detail", []string{`ALTER TABLE reported ADD COLUMN detail TEXT`}},
		// The index dropped rejected records: rebuilt from the full dump.
		{"cvelist_record", "rejected", []string{
			`ALTER TABLE cvelist_record ADD COLUMN rejected INTEGER NOT NULL DEFAULT 0`,
			`DELETE FROM meta WHERE key = '` + keyCVEListBaseline + `'`,
		}},
	} {
		if err := addColumn(ctx, db, m.table, m.column, m.stmts); err != nil {
			return err
		}
	}
	_, err := db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
	return err
}

// addColumn runs stmts in one transaction unless table has column already.
func addColumn(ctx context.Context, db *sql.DB, table, column string, stmts []string) error {
	if ok, err := hasColumn(ctx, db, table, column); err != nil || ok {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // after Commit it does nothing
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func hasColumn(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return n > 0, err
}

func hasDetail(ctx context.Context, db *sql.DB) (bool, error) {
	return hasColumn(ctx, db, "reported", "detail")
}

func (s *Store) Close() error { return s.db.Close() }

// ReadOnly reports whether the store never writes (dry runs, audit).
func (s *Store) ReadOnly() bool { return s.readOnly }

// hasTable reports whether a table exists: a read-only DB is not migrated
// and may predate it.
func (s *Store) hasTable(ctx context.Context, name string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n)
	return n > 0, err
}

// LastSuccess returns the timestamp of the last fully successful run.
func (s *Store) LastSuccess(ctx context.Context) (time.Time, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, keyLastSuccess).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	return t, err == nil, err
}

// SourceWindows returns, per source that failed in an earlier run and has
// not answered since, the window start it must ask again from. A source
// that failed keeps its own window, so the others (and the run) move on
// and nothing it missed is lost.
func (s *Store) SourceWindows(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM meta WHERE key LIKE ?`, keySourceWindow+"%")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // rows.Err reports iteration errors
	out := map[string]time.Time{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		out[strings.TrimPrefix(k, keySourceWindow)] = t
	}
	return out, rows.Err()
}

// SourceWindow is a source's window for the next run: Since is where it
// asks again from after a failure; zero means it answered and follows the
// run's window again.
type SourceWindow struct {
	Source string
	Since  time.Time
}

// Prior is what was last reported for a finding.
type Prior struct {
	ID            string
	Snapshot      finding.Snapshot
	Hash          string
	FirstReported time.Time
	Detail        *Detail // nil for rows written before details were stored
}

// Lookup finds the previously reported record for any of the finding's IDs.
func (s *Store) Lookup(ctx context.Context, product string, ids []string) (*Prior, error) {
	for _, id := range ids {
		var canon string
		err := s.db.QueryRowContext(ctx, `SELECT id FROM reported_alias WHERE product = ? AND alias = ?`, product, id).Scan(&canon)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var (
			snap, hash, first string
			detail            sql.NullString
		)
		err = s.db.QueryRowContext(ctx, `SELECT snapshot, hash, first_reported, `+s.detailColumn(ctx)+` FROM reported WHERE product = ? AND id = ?`,
			product, canon).Scan(&snap, &hash, &first, &detail)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		p := &Prior{ID: canon, Hash: hash}
		if err := json.Unmarshal([]byte(snap), &p.Snapshot); err != nil {
			return nil, fmt.Errorf("decode snapshot %s/%s: %w", product, canon, err)
		}
		if p.FirstReported, err = time.Parse(time.RFC3339Nano, first); err != nil {
			return nil, fmt.Errorf("first_reported %s/%s: %w", product, canon, err)
		}
		if detail.Valid {
			p.Detail = &Detail{}
			if err := json.Unmarshal([]byte(detail.String), p.Detail); err != nil {
				return nil, fmt.Errorf("decode detail %s/%s: %w", product, canon, err)
			}
		}
		return p, nil
	}
	return nil, nil
}

// detailColumn is "detail", or NULL on a read-only DB that predates it.
func (s *Store) detailColumn(ctx context.Context) string {
	if ok, err := hasDetail(ctx, s.db); err == nil && ok {
		return "detail"
	}
	return "NULL"
}

// Baseline records that a product's full advisory history was checked for
// one version and set of catalog selectors (Fingerprint).
type Baseline struct {
	Product     string
	Constraint  string
	Fingerprint string
	CheckedAt   time.Time
}

// Baselines returns the stored baselines by product.
func (s *Store) Baselines(ctx context.Context) (map[string]Baseline, error) {
	out := map[string]Baseline{}
	if ok, err := s.hasTable(ctx, "baseline"); err != nil || !ok {
		return out, err // read-only DB that predates baselines
	}
	rows, err := s.db.QueryContext(ctx, `SELECT product, constraint_, fingerprint, checked_at FROM baseline`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // rows.Err reports iteration errors
	for rows.Next() {
		var (
			b  Baseline
			at string
		)
		if err := rows.Scan(&b.Product, &b.Constraint, &b.Fingerprint, &at); err != nil {
			return nil, err
		}
		if b.CheckedAt, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, fmt.Errorf("baseline %s: %w", b.Product, err)
		}
		out[b.Product] = b
	}
	return out, rows.Err()
}

// PruneBaselines deletes the baselines of products not in keep (removed
// from the stack), so a product added again gets its full history checked.
// It returns the products whose baseline was deleted.
func (s *Store) PruneBaselines(ctx context.Context, keep []string) ([]string, error) {
	if s.readOnly {
		return nil, errors.New("state db is read-only")
	}
	stored, err := s.Baselines(ctx)
	if err != nil {
		return nil, err
	}
	var gone []string
	for _, p := range slices.Sorted(maps.Keys(stored)) {
		if !slices.Contains(keep, p) {
			gone = append(gone, p)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, p := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM baseline WHERE product = ?`, p); err != nil {
			return nil, err
		}
	}
	return gone, tx.Commit()
}

// Record is one reported finding to persist.
type Record struct {
	Product  string
	ID       string
	IDs      []string // canonical ID plus aliases
	PriorID  string   // canonical ID used last time, if different
	Snapshot finding.Snapshot
	Detail   Detail
}

// Detail is what is kept of a reported finding so later runs can list it as
// still open: the affected ranges are re-matched against the current stack.
type Detail struct {
	Finding  finding.Finding `json:"finding"`
	Priority string          `json:"priority"`
	Relevant string          `json:"relevant"`
	Method   string          `json:"method"` // triage method that set Priority and Relevant
	// Constraint is the product's stack.yaml version when the finding was
	// reported. Findings without version data stay open until it changes.
	Constraint string `json:"constraint,omitempty"`
	// Claude's explanation and next step, shown again while it stays open.
	Summary string `json:"summary,omitempty"`
	Action  string `json:"action,omitempty"`
	// The product's exposure and criticality when Priority was set; a
	// stored Claude verdict is weighed again when they change.
	Exposure    string `json:"exposure,omitempty"`
	Criticality string `json:"criticality,omitempty"`
	// Untriaged: Claude was due but gave no verdict (API failure, invalid
	// answer, cost guard, LLM off); a later run with budget left asks again.
	Untriaged bool `json:"untriaged,omitempty"`
}

// NewDetail keeps the fields needed to re-match and present a finding; the
// description and most references are dropped to keep the DB small.
func NewDetail(f finding.Finding, priority, relevant, method, constraint string) Detail {
	f.Description, f.MatchDetail = "", ""
	if len(f.References) > 3 {
		f.References = f.References[:3]
	}
	return Detail{Finding: f, Priority: priority, Relevant: relevant, Method: method, Constraint: constraint}
}

// Reported is a previously reported finding with its stored detail.
type Reported struct {
	Product       string
	ID            string
	FirstReported time.Time
	Detail        Detail
}

// Commit stores reported findings, completed baselines, if setLastSuccess
// the run timestamp, and the sources' own windows, in one transaction.
func (s *Store) Commit(ctx context.Context, at time.Time, recs []Record, baselines []Baseline, setLastSuccess bool, windows ...SourceWindow) error {
	if s.readOnly {
		return errors.New("state db is read-only")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	ts := at.UTC().Format(time.RFC3339Nano)
	for _, r := range recs {
		snap, err := json.Marshal(r.Snapshot)
		if err != nil {
			return err
		}
		detail, err := json.Marshal(r.Detail)
		if err != nil {
			return err
		}
		first, err := collapse(ctx, tx, r, at.UTC())
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO reported (product, id, snapshot, hash, first_reported, last_reported, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (product, id) DO UPDATE SET snapshot = excluded.snapshot, hash = excluded.hash,
				first_reported = excluded.first_reported, last_reported = excluded.last_reported, detail = excluded.detail`,
			r.Product, r.ID, string(snap), r.Snapshot.Hash(), first, ts, string(detail)); err != nil {
			return err
		}
		for _, alias := range r.IDs {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO reported_alias (product, alias, id) VALUES (?, ?, ?)
				ON CONFLICT (product, alias) DO UPDATE SET id = excluded.id`, r.Product, alias, r.ID); err != nil {
				return err
			}
		}
	}
	for _, b := range baselines {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO baseline (product, constraint_, fingerprint, checked_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (product) DO UPDATE SET constraint_ = excluded.constraint_, fingerprint = excluded.fingerprint,
				checked_at = excluded.checked_at`, b.Product, b.Constraint, b.Fingerprint, ts); err != nil {
			return err
		}
	}
	if setLastSuccess {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO meta (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, keyLastSuccess, ts); err != nil {
			return err
		}
	}
	for _, w := range windows {
		key := keySourceWindow + w.Source
		if w.Since.IsZero() {
			if _, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE key = ?`, key); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO meta (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, w.Since.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// collapse folds every stored row of the record's finding into r.ID: the
// prior canonical ID (a GHSA that got a CVE) and rows stored under any of
// its IDs before the sources linked them. It returns the earliest
// first_reported among them, or at.
func collapse(ctx context.Context, tx *sql.Tx, r Record, at time.Time) (string, error) {
	ids := map[string]bool{}
	for _, id := range append([]string{r.ID, r.PriorID}, r.IDs...) {
		if id == "" {
			continue
		}
		ids[id] = true
		var canon string
		err := tx.QueryRowContext(ctx, `SELECT id FROM reported_alias WHERE product = ? AND alias = ?`, r.Product, id).Scan(&canon)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return "", err
		default:
			ids[canon] = true
		}
	}
	first := at
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		var ts string
		err := tx.QueryRowContext(ctx, `SELECT first_reported FROM reported WHERE product = ? AND id = ?`, r.Product, id).Scan(&ts)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return "", err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil && t.Before(first) {
			first = t
		}
		if id == r.ID {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM reported WHERE product = ? AND id = ?`, r.Product, id); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE reported_alias SET id = ? WHERE product = ? AND id = ?`, r.ID, r.Product, id); err != nil {
			return "", err
		}
	}
	return first.Format(time.RFC3339Nano), nil
}

// ListReported returns every reported finding that has a stored detail.
// Rows written before details were stored are skipped; a read-only store
// opened on such an old DB returns nothing.
func (s *Store) ListReported(ctx context.Context) ([]Reported, error) {
	if ok, err := hasDetail(ctx, s.db); err != nil || !ok {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT product, id, first_reported, detail FROM reported WHERE detail IS NOT NULL ORDER BY product, id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // rows.Err reports iteration errors
	var out []Reported
	for rows.Next() {
		var (
			r             Reported
			first, detail string
		)
		if err := rows.Scan(&r.Product, &r.ID, &first, &detail); err != nil {
			return nil, err
		}
		if r.FirstReported, err = time.Parse(time.RFC3339Nano, first); err != nil {
			return nil, fmt.Errorf("first_reported %s/%s: %w", r.Product, r.ID, err)
		}
		if err := json.Unmarshal([]byte(detail), &r.Detail); err != nil {
			return nil, fmt.Errorf("decode detail %s/%s: %w", r.Product, r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetCache implements sources.Cache.
func (s *Store) GetCache(ctx context.Context, key string) ([]byte, time.Time, bool, error) {
	var (
		body []byte
		at   string
	)
	err := s.db.QueryRowContext(ctx, `SELECT body, fetched_at FROM cache WHERE key = ?`, key).Scan(&body, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	return body, t, true, nil
}

// PutCache implements sources.Cache; it is a no-op on a read-only store.
func (s *Store) PutCache(ctx context.Context, key string, body []byte) error {
	if s.readOnly {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cache (key, fetched_at, body) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET fetched_at = excluded.fetched_at, body = excluded.body`,
		key, time.Now().UTC().Format(time.RFC3339Nano), body)
	return err
}

// NewsSeen returns the IDs of a news feed's items already handled (posted,
// or remembered when the feed was first read). Empty: the feed is new.
func (s *Store) NewsSeen(ctx context.Context, feed string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM news_seen WHERE feed = ?`, feed)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// MarkNewsSeen remembers news items as handled; a no-op on a read-only store.
func (s *Store) MarkNewsSeen(ctx context.Context, feed string, ids []string, at time.Time) error {
	if s.readOnly || len(ids) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `INSERT INTO news_seen (feed, id, seen_at) VALUES (?, ?, ?) ON CONFLICT (feed, id) DO NOTHING`,
			feed, id, at.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return tx.Commit()
}
