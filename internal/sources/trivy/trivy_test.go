package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/kube"
	"github.com/vasops/vulnwatch/internal/sources"
)

type obj = map[string]any

func vuln(id, pkg, purl, installed, fixed, sev string, score float64) obj {
	return obj{"vulnerabilityID": id, "resource": pkg, "packagePURL": purl, "installedVersion": installed, "fixedVersion": fixed,
		"severity": sev, "score": score, "title": pkg + ": " + id, "primaryLink": "https://avd.aquasec.com/nvd/" + id,
		"publishedDate": "2026-10-21T21:17:58Z", "lastModifiedDate": "2026-11-03T10:17:13Z"}
}

func vulnReport(server, repo, tag string, vulns ...obj) obj {
	return obj{"report": obj{"registry": obj{"server": server}, "artifact": obj{"repository": repo, "tag": tag}, "vulnerabilities": vulns}}
}

func testConfig() *config.Config {
	return &config.Config{Catalog: map[string]config.CatalogEntry{
		"argocd":  {Images: []string{"quay.io/argoproj/argocd"}},
		"grafana": {Images: []string{"grafana/grafana"}},
	}}
}

func serve(t *testing.T, pages ...[]obj) *kube.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != reportsPath {
			http.NotFound(w, r)
			return
		}
		i := 0
		if c := r.URL.Query().Get("continue"); c != "" {
			i = 1
		}
		meta := obj{}
		if i+1 < len(pages) {
			meta["continue"] = "next"
		}
		json.NewEncoder(w).Encode(obj{"metadata": meta, "items": pages[i]})
	}))
	t.Cleanup(srv.Close)
	return kube.NewForTest(srv.URL, srv.Client())
}

func TestFetch(t *testing.T) {
	c := serve(t,
		[]obj{
			vulnReport("quay.io", "argoproj/argocd", "v3.5.6",
				vuln("CVE-2026-111497", "libbrotli1", "pkg:deb/debian/libbrotli1@1.1.0-2", "1.1.0-2", "1.1.0-2+deb13u1", "HIGH", 7.5),
				vuln("CVE-2026-111497", "brotli-libs", "pkg:apk/alpine/brotli-libs@1.1.0", "1.1.0-r2", "1.1.0-r3", "CRITICAL", 9.1),
				vuln("CVE-2026-9", "libz", "pkg:deb/debian/libz@1", "1", "", "LOW", 3.1),
			),
		},
		[]obj{
			// The same image again (a second pod) and a mirror of grafana.
			vulnReport("quay.io", "argoproj/argocd", "v3.5.6",
				vuln("CVE-2026-111497", "libbrotli1", "pkg:deb/debian/libbrotli1@1.1.0-2", "1.1.0-2", "1.1.0-2+deb13u1", "HIGH", 7.5)),
			vulnReport("index.docker.io", "grafana/grafana", "13.0.5",
				vuln("ghsa-xxxx-yyyy-zzzz", "golang.org/x/net", "pkg:golang/golang.org/x/net@v0.30.0", "v0.30.0", "0.33.0", "MEDIUM", 5.3)),
			vulnReport("ghcr.io", "acme/app", "1.0", vuln("CVE-2026-7", "openssl", "", "3", "3.1", "CRITICAL", 9.8)),
		},
	)
	s := NewWithClient(testConfig(), c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cfg := testConfig()

	fs, err := s.Fetch(context.Background(), sources.Selector{Product: "argocd", Entry: cfg.Catalog["argocd"]}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("one finding per CVE, LOW dropped: %+v", fs)
	}
	f := fs[0]
	if f.ID != "CVE-2026-111497" || f.Severity != finding.SeverityCritical || f.CVSS != 9.1 || len(f.Packages) != 2 ||
		f.Sources[0] != finding.SourceTrivy || !f.ImageOnly() || f.Modified.IsZero() || f.References[0] == "" {
		t.Fatalf("finding: %+v", f)
	}
	want := finding.Package{Image: "quay.io/argoproj/argocd:v3.5.6", Name: "libbrotli1", Type: "deb", Installed: "1.1.0-2", Fixed: "1.1.0-2+deb13u1"}
	if f.Packages[0] != want {
		t.Fatalf("package: %+v", f.Packages[0])
	}

	fs, err = s.Fetch(context.Background(), sources.Selector{Product: "grafana", Entry: cfg.Catalog["grafana"]}, time.Time{})
	if err != nil || len(fs) != 1 || fs[0].ID != "GHSA-XXXX-YYYY-ZZZZ" || fs[0].Packages[0].Image != "docker.io/grafana/grafana:13.0.5" {
		t.Fatalf("grafana (docker.io mirror): %+v %v", fs, err)
	}
	if got := s.UnmatchedImages(); len(got) != 1 || got[0] != "ghcr.io/acme/app:1.0" {
		t.Fatalf("unmatched: %v", got)
	}
}

func TestFetchWithoutImagesOrCluster(t *testing.T) {
	s := New(testConfig(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.client = func() (*kube.Client, error) { return nil, errors.New("not running in a Kubernetes pod") }
	if fs, err := s.Fetch(context.Background(), sources.Selector{Product: "postgresql"}, time.Time{}); fs != nil || err != nil {
		t.Fatalf("a product without images needs no cluster: %v %v", fs, err)
	}
	_, err := s.Fetch(context.Background(), sources.Selector{Product: "argocd", Entry: testConfig().Catalog["argocd"]}, time.Time{})
	if err == nil {
		t.Fatal("want an error outside a cluster")
	}
}
