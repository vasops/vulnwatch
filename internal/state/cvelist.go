package state

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// The cvelist index: the match keys of every CVE record (vendor and product
// names, CPEs, package names, as the cvelist source spells them) and when
// the record was last updated, so a product's records are found without
// reading the 300,000 records again.

// Meta keys of the index.
const (
	keyCVEListBaseline = "cvelist_baseline"
	keyCVEListApplied  = "cvelist_applied"
)

// cvelistTime stores dateUpdated with a fixed width, so text order is time order.
const cvelistTime = "2006-01-02T15:04:05.000Z"

// CVEListEntry is one CVE record in the index.
type CVEListEntry struct {
	ID      string
	Updated time.Time // the record's dateUpdated
	Keys    []string
	Removed bool // rejected: kept without keys, so never matched
}

// CVEListMeta says how far the index is: the day of the full dump it was
// built from and the last day whose changes are applied completely
// (YYYY-MM-DD; empty when there is no index yet).
type CVEListMeta struct {
	Baseline string
	Applied  string
}

// CVEListMeta returns how far the index is.
func (s *Store) CVEListMeta(ctx context.Context) (CVEListMeta, error) {
	var m CVEListMeta
	for _, kv := range []struct {
		key string
		dst *string
	}{{keyCVEListBaseline, &m.Baseline}, {keyCVEListApplied, &m.Applied}} {
		err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, kv.key).Scan(kv.dst)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return m, err
		}
	}
	return m, nil
}

// CVEListLookup returns the records with any of the keys, updated at or
// after since (zero: all), with their update time.
func (s *Store) CVEListLookup(ctx context.Context, keys []string, since time.Time) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if len(keys) == 0 {
		return out, nil
	}
	if ok, err := s.hasTable(ctx, "cvelist_key"); err != nil || !ok {
		return out, err // read-only DB that predates the index
	}
	for _, k := range keys {
		if err := s.cvelistKey(ctx, k, since, out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// cvelistKey adds the records with one key to out.
func (s *Store) cvelistKey(ctx context.Context, key string, since time.Time, out map[string]time.Time) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.updated FROM cvelist_key k JOIN cvelist_record r ON r.id = k.id
		WHERE k.key = ? AND r.updated >= ?`, key, since.UTC().Format(cvelistTime))
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }() // rows.Err reports iteration errors
	for rows.Next() {
		var id, at string
		if err := rows.Scan(&id, &at); err != nil {
			return err
		}
		t, err := time.Parse(cvelistTime, at)
		if err != nil {
			return err
		}
		out[id] = t
	}
	return rows.Err()
}

// CVEListRejected returns which of ids the CVE list marks as rejected.
func (s *Store) CVEListRejected(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if ok, err := hasColumn(ctx, s.db, "cvelist_record", "rejected"); err != nil || !ok {
		return out, err // read-only DB that predates it
	}
	for _, id := range ids {
		var n int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM cvelist_record WHERE id = ? AND rejected = 1`, id).Scan(&n)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			out[id] = true
		}
	}
	return out, nil
}

// CVEListUpdate is one transaction on the index: the records of one dump
// or delta archive.
type CVEListUpdate struct {
	tx                         *sql.Tx
	reset                      bool
	updated, delKeys           *sql.Stmt
	putRec, putKey, putMetaVal *sql.Stmt
}

// UpdateCVEList starts an update of the index; reset empties it first (a
// new full dump). Only one update runs at a time: it holds the connection.
func (s *Store) UpdateCVEList(ctx context.Context, reset bool) (*CVEListUpdate, error) {
	if s.readOnly {
		return nil, errors.New("state db is read-only")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	u := &CVEListUpdate{tx: tx, reset: reset}
	if reset {
		for _, q := range []string{`DELETE FROM cvelist_key`, `DELETE FROM cvelist_record`} {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				_ = tx.Rollback()
				return nil, err
			}
		}
	}
	for _, p := range []struct {
		dst **sql.Stmt
		q   string
	}{
		{&u.updated, `SELECT updated FROM cvelist_record WHERE id = ?`},
		{&u.delKeys, `DELETE FROM cvelist_key WHERE id = ?`},
		{&u.putRec, `INSERT INTO cvelist_record (id, updated, rejected) VALUES (?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET updated = excluded.updated, rejected = excluded.rejected`},
		{&u.putKey, `INSERT OR IGNORE INTO cvelist_key (key, id) VALUES (?, ?)`},
		{&u.putMetaVal, `INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`},
	} {
		if *p.dst, err = tx.PrepareContext(ctx, p.q); err != nil {
			_ = tx.Rollback()
			return nil, err
		}
	}
	return u, nil
}

// Put adds or replaces one record; a rejected one keeps no keys. A record
// already stored with a later update time is kept, so archives may be
// applied in any order and more than once.
func (u *CVEListUpdate) Put(ctx context.Context, e CVEListEntry) error {
	at := e.Updated.UTC().Format(cvelistTime)
	if !u.reset {
		var cur string
		err := u.updated.QueryRowContext(ctx, e.ID).Scan(&cur)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case cur > at:
			return nil
		}
		if _, err := u.delKeys.ExecContext(ctx, e.ID); err != nil {
			return err
		}
	}
	if _, err := u.putRec.ExecContext(ctx, e.ID, at, e.Removed); err != nil {
		return err
	}
	if e.Removed {
		return nil
	}
	for _, k := range e.Keys {
		if _, err := u.putKey.ExecContext(ctx, k, e.ID); err != nil {
			return err
		}
	}
	return nil
}

// Commit stores the update with the index's new meta (empty fields are
// left as they are).
func (u *CVEListUpdate) Commit(ctx context.Context, m CVEListMeta) error {
	for _, kv := range [][2]string{{keyCVEListBaseline, m.Baseline}, {keyCVEListApplied, m.Applied}} {
		if kv[1] == "" {
			continue
		}
		if _, err := u.putMetaVal.ExecContext(ctx, kv[0], kv[1]); err != nil {
			_ = u.tx.Rollback()
			return err
		}
	}
	return u.tx.Commit()
}

// Rollback discards the update; after Commit it does nothing.
func (u *CVEListUpdate) Rollback() { _ = u.tx.Rollback() }
