package kev

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
)

type memCache struct {
	body []byte
	at   time.Time
}

func (m *memCache) GetCache(context.Context, string) ([]byte, time.Time, bool, error) {
	return m.body, m.at, m.body != nil, nil
}
func (m *memCache) PutCache(_ context.Context, _ string, b []byte) error {
	m.body, m.at = b, time.Now()
	return nil
}

func TestEnrich(t *testing.T) {
	fixture, err := os.ReadFile("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write(fixture)
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	cache := &memCache{}
	e := New(config.KEVSource{URL: srv.URL, CacheTTL: config.Duration(time.Hour)}, client, cache, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for range 2 {
		fs := []finding.Finding{
			{ID: "GHSA-x", Aliases: []string{"CVE-2016-3081"}},
			{ID: "CVE-2026-0001"},
		}
		if err := e.Enrich(context.Background(), fs); err != nil {
			t.Fatal(err)
		}
		if !fs[0].KEV || fs[0].KEVDateAdded == "" || fs[1].KEV {
			t.Fatalf("%+v", fs)
		}
	}
	if calls != 1 {
		t.Fatalf("cache not used: %d calls", calls)
	}
}

func TestEnrichFallsBackToStaleCache(t *testing.T) {
	fixture, err := os.ReadFile("testdata/kev.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tests := []struct {
		name      string
		status    int    // download answer
		body      string // download body; the fixture if empty
		cache     *memCache
		wantErr   bool
		wantKEV   bool
		wantCalls int
	}{
		{"fresh cache, no download", http.StatusOK, "", &memCache{body: fixture, at: now}, false, true, 0},
		{"stale cache, download works", http.StatusOK, "", &memCache{body: []byte(`{"vulnerabilities":[]}`), at: now.Add(-30 * 24 * time.Hour)}, false, true, 1},
		{"stale cache, download fails", http.StatusBadGateway, "", &memCache{body: fixture, at: now.Add(-30 * 24 * time.Hour)}, true, true, 1},
		{"stale cache, download is garbage", http.StatusOK, "<html>", &memCache{body: fixture, at: now.Add(-30 * 24 * time.Hour)}, true, true, 1},
		{"no cache, download fails", http.StatusBadGateway, "", &memCache{}, true, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tt.status)
				if tt.body != "" {
					w.Write([]byte(tt.body))
				} else {
					w.Write(fixture)
				}
			}))
			defer srv.Close()
			client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
			e := New(config.KEVSource{URL: srv.URL, CacheTTL: config.Duration(time.Hour)}, client, tt.cache, slog.New(slog.NewTextHandler(io.Discard, nil)))
			fs := []finding.Finding{{ID: "GHSA-x", Aliases: []string{"CVE-2016-3081"}}}
			err := e.Enrich(context.Background(), fs)
			if (err != nil) != tt.wantErr || fs[0].KEV != tt.wantKEV || calls != tt.wantCalls {
				t.Fatalf("err=%v kev=%v calls=%d", err, fs[0].KEV, calls)
			}
			if err != nil && tt.wantKEV && !strings.Contains(err.Error(), "used the cached catalog from "+tt.cache.at.UTC().Format(time.DateOnly)+" (30d old)") {
				t.Fatalf("a stale catalog must be named in the error: %v", err)
			}
			if tt.status == http.StatusOK && tt.body == "" && tt.wantCalls == 1 && string(tt.cache.body) != string(fixture) {
				t.Fatal("a downloaded catalog must replace the cache")
			}
			if tt.body != "" && string(tt.cache.body) != string(fixture) {
				t.Fatal("an invalid download must not replace the cache")
			}
		})
	}
}
