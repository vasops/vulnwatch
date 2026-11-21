package k8sfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

func TestFetch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/feed.json")
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
	src := New(config.K8sFeedSource{URL: srv.URL, Products: []string{"kubernetes", "rke2"}}, client)
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range []string{"kubernetes", "rke2"} {
		fs, err := src.Fetch(context.Background(), sources.Selector{Product: p}, since)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 2 || fs[0].Product != p {
			t.Fatalf("%s: %+v", p, fs)
		}
		if fs[0].ID != "CVE-2026-76654" || fs[0].CVSS != 5.8 {
			t.Fatalf("mapping: %+v", fs[0])
		}
	}
	if calls != 1 {
		t.Fatalf("feed fetched %d times, want once", calls)
	}
	fs, _ := src.Fetch(context.Background(), sources.Selector{Product: "argocd"}, since)
	if fs != nil {
		t.Fatal("unrelated product got findings")
	}
}
