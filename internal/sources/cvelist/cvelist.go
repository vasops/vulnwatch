// Package cvelist reads CVE records as the CNAs publish them, from the CVE
// Program's cvelistV5 repository, with CISA's Vulnrichment (CVSS, SSVC) in
// the same record. Records often carry the vendor's affected versions on
// the day they are published, before NVD has analysed them.
//
// A product's records are found through an index in the state DB (the
// match keys of every record): built from the full dump on the first run,
// updated every run from the daily and hourly delta releases. A product
// matches by its catalog cvelist: names (the CNA's vendor and product),
// nvd: CPEs and osv: package names; only its own affected entries of a
// record count. Changed records are read from the deltas, others from
// {records_url}/<year>/<n>xxx/<id>.json.
//
// Feed: GET {releases_url} (GitHub releases API, the only request that may
// carry the token), assets via their browser_download_url.
package cvelist

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/state"
)

const (
	Name = "cvelist"
	// fetchers bounds the concurrent single-record downloads of the source.
	fetchers = 8
)

// Index is the match index in the state DB (*state.Store).
type Index interface {
	ReadOnly() bool
	CVEListMeta(ctx context.Context) (state.CVEListMeta, error)
	CVEListLookup(ctx context.Context, keys []string, since time.Time) (map[string]time.Time, error)
	UpdateCVEList(ctx context.Context, reset bool) (*state.CVEListUpdate, error)
}

type Source struct {
	cfg    config.CVEListSource
	client *httpx.Client
	token  string
	index  Index
	log    *slog.Logger
	now    func() time.Time
	sem    chan struct{}

	once sync.Once
	err  error // of prepare: fails every fetch of the run
	// Set by prepare, read-only afterwards.
	dir     string                        // this run's directory in work_dir
	files   map[string]archived           // the newest copy of each record read this run
	changed map[string]state.CVEListEntry // records of this run's deltas
	closers []io.Closer
}

// archived is a record in an archive of this run.
type archived struct {
	file    *zip.File
	updated time.Time
}

// New builds the source; index may be nil (no state DB: every fetch fails).
func New(cfg config.CVEListSource, client *httpx.Client, getenv func(string) string, index Index, log *slog.Logger) *Source {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Source{
		cfg: cfg, client: client, index: index, log: log, now: time.Now,
		sem:   make(chan struct{}, fetchers),
		files: map[string]archived{}, changed: map[string]state.CVEListEntry{},
	}
	if cfg.TokenEnv != "" {
		s.token = getenv(cfg.TokenEnv)
	}
	if s.cfg.WorkDir == "" {
		s.cfg.WorkDir = filepath.Join(os.TempDir(), "vulnwatch-cvelist")
	}
	return s
}

func (s *Source) Name() string { return Name }

// Fetch returns the product's records updated since since (zero: all). The
// index is brought up to date by the first fetch of the run; when that
// fails, every fetch fails.
func (s *Source) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	m := newMatcher(sel.Entry)
	if m.empty() {
		return nil, nil
	}
	s.once.Do(func() { s.err = s.prepare(ctx) })
	if s.err != nil {
		return nil, s.err
	}
	ids, err := s.lookup(ctx, m, since)
	if err != nil {
		return nil, err
	}
	recs := make([]*record, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchers)
	for i, id := range ids {
		g.Go(func() error {
			r, err := s.record(gctx, id)
			var bad *badRecordError
			if errors.As(err, &bad) {
				s.log.Warn("cvelist record skipped", "id", id, "err", err)
				return nil
			}
			recs[i] = r
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, r := range recs {
		if r == nil {
			continue
		}
		if f, ok := toFinding(sel.Product, r, m); ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// lookup returns the IDs of the product's records updated since since:
// the index, with this run's changes over it (a read-only index lacks them).
func (s *Source) lookup(ctx context.Context, m matcher, since time.Time) ([]string, error) {
	hits, err := s.index.CVEListLookup(ctx, m.keys, since)
	if err != nil {
		return nil, fmt.Errorf("index lookup: %w", err)
	}
	for id, e := range s.changed {
		if !e.Removed && !e.Updated.Before(since) && m.hasKey(e.Keys) {
			hits[id] = e.Updated
		} else {
			delete(hits, id)
		}
	}
	return slices.Sorted(maps.Keys(hits)), nil
}

// badRecordError is a record that doesn't parse: skipped, not a failure.
type badRecordError struct{ err error }

func (e *badRecordError) Error() string { return e.err.Error() }

// record reads a record from this run's archives or from records_url.
func (s *Source) record(ctx context.Context, id string) (*record, error) {
	if a, ok := s.files[id]; ok {
		r, err := readRecord(a.file)
		if err != nil {
			return nil, &badRecordError{err}
		}
		return r, nil
	}
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var b json.RawMessage
	if _, err := s.client.GetJSON(ctx, strings.TrimSuffix(s.cfg.RecordsURL, "/")+"/"+path(id), nil, &b); err != nil {
		return nil, err
	}
	r, err := decode(b)
	if err != nil {
		return nil, &badRecordError{fmt.Errorf("%s: %w", id, err)}
	}
	return r, nil
}

// Close closes this run's archives and removes its directory.
func (s *Source) Close() error {
	var errs []error
	for _, c := range s.closers {
		errs = append(errs, c.Close())
	}
	if s.dir != "" {
		errs = append(errs, os.RemoveAll(s.dir))
	}
	return errors.Join(errs...)
}
