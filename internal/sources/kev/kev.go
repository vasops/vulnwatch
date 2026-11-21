// Package kev enriches findings with CISA Known Exploited Vulnerabilities status.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

const (
	Name     = "kev"
	cacheKey = "kev:catalog"
)

type Enricher struct {
	cfg    config.KEVSource
	client *httpx.Client
	cache  sources.Cache // optional
	log    *slog.Logger
	now    func() time.Time
}

func New(cfg config.KEVSource, client *httpx.Client, cache sources.Cache, log *slog.Logger) *Enricher {
	return &Enricher{cfg: cfg, client: client, cache: cache, log: log, now: time.Now}
}

func (e *Enricher) Name() string { return Name }

type catalog struct {
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// Enrich flags the findings the catalog lists. When only a stale cached
// catalog could be read, it is applied and the failed download is still
// returned as an error, so the run reports the source as failing.
func (e *Enricher) Enrich(ctx context.Context, fs []finding.Finding) error {
	added, err := e.load(ctx)
	if added == nil {
		return err
	}
	for i := range fs {
		f := &fs[i]
		for _, id := range f.CVEs() {
			if d, ok := added[id]; ok {
				f.KEV, f.KEVDateAdded = true, d
				break
			}
		}
	}
	return err
}

// load returns the catalog (CVE ID to date added): cached while younger
// than cache_ttl, otherwise downloaded. When the download fails, a cached
// catalog of any age is returned along with an error saying how old it is;
// without one, only the error.
func (e *Enricher) load(ctx context.Context) (map[string]string, error) {
	var (
		stale   map[string]string
		staleAt time.Time
	)
	if e.cache != nil {
		body, at, ok, err := e.cache.GetCache(ctx, cacheKey)
		switch {
		case err != nil:
			e.log.Warn("KEV cache read failed", "source", Name, "err", err)
		case ok:
			if c, err := decode(body); err == nil {
				if e.now().Sub(at) < e.cfg.CacheTTL.D() {
					return c, nil
				}
				stale, staleAt = c, at
			}
		}
	}
	added, err := e.download(ctx)
	if err != nil {
		if stale == nil || ctx.Err() != nil {
			return nil, err
		}
		age := e.now().Sub(staleAt)
		return stale, fmt.Errorf("KEV download failed; used the cached catalog from %s (%dd old): %w",
			staleAt.UTC().Format(time.DateOnly), int(age.Hours()/24), err)
	}
	return added, nil
}

func decode(body []byte) (map[string]string, error) {
	var c catalog
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("decode KEV catalog: %w", err)
	}
	added := make(map[string]string, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		added[v.CVEID] = v.DateAdded
	}
	return added, nil
}

// download fetches and decodes the catalog; only a valid one is cached.
func (e *Enricher) download(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	body, _, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	added, err := decode(body)
	if err != nil {
		return nil, err
	}
	if e.cache != nil {
		if err := e.cache.PutCache(ctx, cacheKey, body); err != nil {
			e.log.Warn("KEV cache write failed", "source", Name, "err", err)
		}
	}
	return added, nil
}
