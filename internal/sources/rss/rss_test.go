package rss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

func TestFetch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/feed.xml")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.Write(fixture)
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	src := New(client)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fs, err := src.Fetch(context.Background(), sources.Selector{Product: "drupal", Entry: config.CatalogEntry{RSS: []string{srv.URL}}}, since)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings", len(fs))
	}
	if fs[0].ID != "CVE-2026-1111" || !slices.Contains(fs[0].Aliases, "https://vendor.example/sa-core-2026-004") {
		t.Fatalf("single CVE item: %+v", fs[0])
	}
	if fs[0].Description != "CVE: CVE-2026-1111. Versions < 10.4.9 are affected." {
		t.Fatalf("html not stripped: %q", fs[0].Description)
	}
	if fs[1].ID != "https://vendor.example/releases/18-4-2" || len(fs[1].Related) != 3 || len(fs[1].Aliases) != 0 {
		t.Fatalf("multi CVE item: %+v", fs[1])
	}
}

func TestFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	_, err := New(client).Fetch(context.Background(), sources.Selector{Entry: config.CatalogEntry{RSS: []string{srv.URL}}}, time.Time{})
	if err == nil {
		t.Fatal("want error")
	}
}

func TestParseErrorRedactsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not a feed"))
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	_, err := New(client).Fetch(context.Background(), sources.Selector{Entry: config.CatalogEntry{RSS: []string{srv.URL + "/feed?token=s3cret"}}}, time.Time{})
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), "token=xxxxx") {
		t.Fatalf("want a parse error with the token redacted, got %v", err)
	}
}
