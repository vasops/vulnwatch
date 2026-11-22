package helmchart

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

// tgz builds a gzipped tarball from path -> content.
func tgz(t testing.TB, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

// stackChart is a kube-prometheus-stack-like chart: one subchart as a
// directory, one as a nested archive.
func stackChart(t *testing.T) []byte {
	nested := tgz(t, map[string]string{
		"node-exporter/Chart.yaml": "name: node-exporter\nversion: 4.55.0\nappVersion: 1.10.2\n",
	})
	return tgz(t, map[string]string{
		"stack/Chart.yaml":                 "name: stack\nversion: 84.1.0\nappVersion: v0.88.1\n",
		"stack/values.yaml":                "prometheus:\n  image:\n    tag: v3.9.1-distroless\nempty:\n  tag: ''\ntmpl:\n  tag: 'v{{ .Chart.Version }}'\n",
		"stack/templates/x.yaml":           "ignored",
		"stack/charts/grafana/Chart.yaml":  "name: grafana\nversion: 12.4.8\nappVersion: 13.0.5\n",
		"stack/charts/grafana/values.yaml": "image:\n  tag: 13.0.5@sha256:abc\n",
		"stack/charts/node-exporter.tgz":   string(nested),
	})
}

func TestParseAndVersions(t *testing.T) {
	c, err := Parse(stackChart(t), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "stack" || c.AppVersion != "v0.88.1" || len(c.Subcharts) != 2 || c.Subcharts["node-exporter"].AppVersion != "1.10.2" {
		t.Fatalf("parsed: %+v", c)
	}
	m := config.HelmChart{
		"operator":      {Kind: config.FromAppVersion},
		"chart":         {Kind: config.FromChartVersion},
		"prometheus":    {Kind: config.FromValues, Values: "prometheus.image.tag"},
		"grafana":       {Kind: config.FromSubchart, Subchart: "grafana"},
		"grafana-image": {Kind: config.FromSubchart, Subchart: "grafana", Values: "image.tag"},
		"node-exporter": {Kind: config.FromSubchart, Subchart: "node-exporter"},
	}
	r := config.HelmRelease{Chart: "stack", Version: "84.1.0", Versions: map[string]string{"node-exporter": "1.12.0", "extra": "9.9"}}
	pv, err := Versions(c, r, m)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pv {
		got[p.Product] = p.Version
	}
	want := map[string]string{
		"operator": "v0.88.1", "chart": "84.1.0", "prometheus": "v3.9.1", "grafana": "13.0.5",
		"grafana-image": "13.0.5", "node-exporter": "1.12.0", "extra": "9.9",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected products: %v", got)
	}
}

func TestVersionsErrors(t *testing.T) {
	c, err := Parse(stackChart(t), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		from config.VersionFrom
		want string
	}{
		{config.VersionFrom{Kind: config.FromValues, Values: "empty.tag"}, "is empty"},
		{config.VersionFrom{Kind: config.FromValues, Values: "tmpl.tag"}, "is a template"},
		{config.VersionFrom{Kind: config.FromValues, Values: "prometheus.nope"}, `key "nope" not found`},
		{config.VersionFrom{Kind: config.FromValues, Values: "prometheus.image"}, "not a string"},
		{config.VersionFrom{Kind: config.FromSubchart, Subchart: "loki"}, `no subchart "loki"`},
	}
	for _, tt := range tests {
		_, err := Versions(c, config.HelmRelease{Chart: "stack", Version: "1"}, config.HelmChart{"p": tt.from})
		if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "versions.p") {
			t.Errorf("%v: want %q with override hint, got %v", tt.from, tt.want, err)
		}
	}
}

func TestValuesTag(t *testing.T) {
	tests := []struct {
		tag  any
		want string
	}{
		{"1.2.3", "1.2.3"},
		{"v3.9.1-distroless", "v3.9.1"},
		{"17.4-7-bullseye", "17.4"},
		{"8.2.1-alpine", "8.2.1"},
		{"11.4.5-debian-12", "11.4.5"},
		{"13.0.5@sha256:abc", "13.0.5"},
		{"1.2.3-rc1", "1.2.3-rc1"},
		{"2.0.0-beta.2", "2.0.0-beta.2"},
		{"v1.30.0-alpha.1", "v1.30.0-alpha.1"},
		{"3.0.0-RC2", "3.0.0-RC2"},
		{"1.2.3-rc.1-alpine", "1.2.3-rc.1"},
		{"4.0.0-preview.3", "4.0.0-preview.3"},
		{"5.1.0-pre", "5.1.0-pre"},
		{"1.2.3-prerelease", "1.2.3"},
		{"latest", "latest"},
		{17.4, "17.4"},
	}
	for _, tt := range tests {
		got, err := valuesTag(map[string]any{"image": map[string]any{"tag": tt.tag}}, "image.tag")
		if err != nil || got != tt.want {
			t.Errorf("%v: got %q %v, want %q", tt.tag, got, err, tt.want)
		}
	}
}

func TestParseLimits(t *testing.T) {
	if _, err := Parse(stackChart(t), 50); err == nil || !strings.Contains(err.Error(), "more than 50 bytes") {
		t.Fatalf("size limit: %v", err)
	}
	if _, err := Parse([]byte("not gzip"), 1<<20); err == nil {
		t.Fatal("want error for non-gzip input")
	}
	if _, err := Parse(tgz(t, map[string]string{"a/b/Chart.yaml": "name: x"}), 1<<20); err == nil {
		t.Fatal("want error without a root Chart.yaml")
	}
}

type memCache map[string][]byte

func (m memCache) GetCache(_ context.Context, k string) ([]byte, time.Time, bool, error) {
	b, ok := m[k]
	return b, time.Time{}, ok, nil
}
func (m memCache) PutCache(_ context.Context, k string, b []byte) error { m[k] = b; return nil }

func newTestFetcher(cache sources.Cache) *Fetcher {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := httpx.New(config.HTTP{UserAgent: "test", Timeout: config.Duration(5 * time.Second), MaxResponseBytes: 1 << 20}, "test", log)
	return NewFetcher(client, cache, 1<<20, log)
}

func TestFetchRepoAndCache(t *testing.T) {
	archive := stackChart(t)
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/charts/index.yaml":
			// Relative chart URL, version listed with a v prefix.
			w.Write([]byte("apiVersion: v1\nentries:\n  stack:\n    - version: v84.1.0\n      urls: [pkg/stack-84.1.0.tgz]\n    - version: 1.0.0\n      urls: [pkg/old.tgz]\n"))
		case "/charts/pkg/stack-84.1.0.tgz":
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cache := memCache{}
	f := newTestFetcher(cache)
	r := config.HelmRelease{Repo: srv.URL + "/charts", Chart: "stack", Version: "84.1.0"}
	c, err := f.Fetch(context.Background(), r)
	if err != nil || c.AppVersion != "v0.88.1" || hits != 2 {
		t.Fatalf("fetch: %+v %v hits=%d", c, err, hits)
	}
	if c, err := f.Fetch(context.Background(), r); err != nil || c.Subcharts["grafana"].AppVersion != "13.0.5" || hits != 2 {
		t.Fatalf("second fetch must come from cache: %v hits=%d", err, hits)
	}
	for _, tt := range []struct {
		r    config.HelmRelease
		want string
	}{
		{config.HelmRelease{Repo: srv.URL + "/charts", Chart: "stack", Version: "9.9.9"}, "version 9.9.9 not found"},
		{config.HelmRelease{Repo: srv.URL + "/charts", Chart: "other", Version: "1"}, `chart "other" not found`},
		{config.HelmRelease{Repo: srv.URL + "/missing", Chart: "stack", Version: "1"}, "HTTP 404"},
	} {
		if _, err := f.Fetch(context.Background(), tt.r); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%v: want %q, got %v", tt.r, tt.want, err)
		}
	}
}

func TestFetchOCI(t *testing.T) {
	f := newTestFetcher(nil)
	var gotRef string
	f.pullOCI = func(_ context.Context, ref string) ([]byte, error) {
		gotRef = ref
		return stackChart(t), nil
	}
	if _, err := f.Fetch(context.Background(), config.HelmRelease{Repo: "oci://ghcr.io/org/charts/", Chart: "stack", Version: "1.0.0+build.1"}); err != nil {
		t.Fatal(err)
	}
	if gotRef != "ghcr.io/org/charts/stack:1.0.0_build.1" {
		t.Fatalf("OCI reference: %q", gotRef)
	}
	_, err := f.Fetch(context.Background(), config.HelmRelease{Repo: "oci://ghcr.io/org", Chart: "other", Version: "1"})
	if err == nil || !strings.Contains(err.Error(), `archive contains chart "stack"`) {
		t.Fatalf("want chart name mismatch, got %v", err)
	}
}
