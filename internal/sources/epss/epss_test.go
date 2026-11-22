package epss

import (
	"context"
	"fmt"
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

func TestEnrich(t *testing.T) {
	fixture, err := os.ReadFile("testdata/epss.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("cve"), "CVE-2021-44228") {
			t.Errorf("query: %s", r.URL.RawQuery)
		}
		w.Write(fixture)
	}))
	defer srv.Close()
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	fs := []finding.Finding{{ID: "CVE-2021-44228"}, {ID: "GHSA-y", Aliases: []string{"CVE-2025-47933"}}, {ID: "GHSA-nocve"}}
	if err := New(config.EPSSSource{BaseURL: srv.URL, BatchSize: 100}, client).Enrich(context.Background(), fs); err != nil {
		t.Fatal(err)
	}
	if fs[0].EPSS < 0.99 || fs[0].EPSSPercentile != 1 || fs[1].EPSS == 0 || fs[2].EPSS != 0 {
		t.Fatalf("%+v", fs)
	}
}

func TestChunk(t *testing.T) {
	var ids []string
	for i := range 250 {
		ids = append(ids, fmt.Sprintf("CVE-2026-%05d", i))
	}
	byCount := chunk(ids, 100, 100000)
	if len(byCount) != 3 || len(byCount[0]) != 100 {
		t.Fatalf("count chunking: %d", len(byCount))
	}
	for _, c := range chunk(ids, 1000, 1900) {
		if l := len(strings.Join(c, ",")); l > 1900 {
			t.Fatalf("chunk too long: %d", l)
		}
	}
}
