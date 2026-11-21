package news

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
)

func serve(t *testing.T, fixture, contentType string) string {
	t.Helper()
	body, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func client() *httpx.Client {
	return httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
}

func TestFetchRHSB(t *testing.T) {
	url := serve(t, "testdata/rhsb.html", "text/html")
	items, err := Fetch(context.Background(), client(), config.NewsFeed{Name: "Red Hat", URL: url + "/security/vulnerabilities", Format: FormatRHSB})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items: %+v", len(items), items)
	}
	want := Item{
		Feed: "Red Hat", ID: "RHSB-2026-018",
		Title: `RHSB-2026-018 Remote Code Execution via memory corruption on x86-64 systems - OpenJDK (CVE-2026-114938) - "java4shell"`,
		Link:  url + "/security/vulnerabilities/RHSB-2026-018",
		CVEs:  []string{"CVE-2026-114938"},
	}
	if !reflect.DeepEqual(items[0], want) {
		t.Fatalf("got  %+v\nwant %+v", items[0], want)
	}
	if items[2].ID != "RHSB-2026-016" {
		t.Fatalf("third: %+v", items[2])
	}
}

func TestFetchRHSBLayoutChanged(t *testing.T) {
	url := serve(t, "testdata/cisa-alerts.xml", "text/html")
	if _, err := Fetch(context.Background(), client(), config.NewsFeed{Name: "Red Hat", URL: url, Format: FormatRHSB}); err == nil {
		t.Fatal("want an error for a page without bulletins")
	}
}

func TestFetchRSSExcludeTitle(t *testing.T) {
	url := serve(t, "testdata/cisa-alerts.xml", "application/rss+xml")
	items, err := Fetch(context.Background(), client(), config.NewsFeed{
		Name: "CISA", URL: url, Format: FormatRSS, ExcludeTitle: `(?i)^CISA Adds .* Known Exploited Vulnerabilit`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items: %+v", len(items), items)
	}
	it := items[0]
	if it.Title != "Critical Java Vulnerability Requires Immediate Patching" || it.ID == "" || it.Published.IsZero() {
		t.Fatalf("item: %+v", it)
	}
	if it.Link != "https://www.cisa.gov/news-events/alerts/2026/11/17/critical-java-vulnerability-requires-immediate-patching" {
		t.Fatalf("link: %s", it.Link)
	}
}

func TestMatcher(t *testing.T) {
	scope := func(tenant, env string) config.Scope {
		return config.Scope{Tenant: tenant, Environment: env, Remote: true}
	}
	products := []catalog.Product{
		{Name: "java", Entry: config.CatalogEntry{Aliases: []string{"openjdk", "jdk"}}, Scope: scope("vasops", "prod")},
		{Name: "java", Entry: config.CatalogEntry{Aliases: []string{"openjdk", "jdk"}}, Scope: scope("acme", "infra")},
		{Name: "java", Entry: config.CatalogEntry{Aliases: []string{"openjdk", "jdk"}}, Scope: scope("acme", "infra")},
		{Name: "nginx", Scope: scope("vasops", "prod")},
		{Name: "ingress-nginx", Scope: scope("acme", "prod")},
		{Name: "envoy", Scope: scope("acme", "prod")},
		{Name: "go", Entry: config.CatalogEntry{Aliases: []string{"golang"}}, Scope: scope("vasops", "prod")},
		{Name: "debian-13-kernel", OS: &config.StackOS{Name: "debian", Release: "13"}, Scope: scope("vasops", "prod")},
		{Name: "gitlab-ce", Scope: scope("vasops", "prod")},
	}
	m := NewMatcher(products)
	for _, tt := range []struct {
		text string
		want []string
	}{
		{"RHSB-2026-018 Remote Code Execution - OpenJDK (CVE-2026-114938)", []string{"java"}},
		{"Critical Java Vulnerability Requires Immediate Patching", []string{"java"}},
		{"HTTP/2 HPACK Denial of Service - httpd, nginx, Envoy", []string{"envoy", "nginx"}},
		{"Use-after-free - Linux kernel IPv4", []string{"debian-13-kernel"}},
		{"Go back to the JavaScript engine", nil}, // "go" is too short, JavaScript is not Java
		{"Golang toolchain flaw", []string{"go"}},
		{"GitLab CE patch release", []string{"gitlab-ce"}},
		{"Apache HTTP Server", nil},
	} {
		var got []string
		for _, h := range m.Match(tt.text) {
			got = append(got, h.Product)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: got %v, want %v", tt.text, got, tt.want)
		}
	}
	hits := m.Match("OpenJDK")
	if want := []config.Scope{scope("acme", "infra"), scope("vasops", "prod")}; len(hits) != 1 || !reflect.DeepEqual(hits[0].Scopes, want) {
		t.Fatalf("scopes: %+v, want %v", hits, want)
	}
}

func TestFetchCERTEU(t *testing.T) {
	url := serve(t, "testdata/cert-eu.xml", "text/xml; charset=utf-8")
	items, err := Fetch(context.Background(), client(), config.NewsFeed{Name: "CERT-EU", URL: url, Format: FormatRSS})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items: %+v", len(items), items)
	}
	it := items[0]
	if it.ID != "security-advisories-10958" || it.Title != "2026-021: High Severity Vulnerability in Java SE and OpenJDK" ||
		it.Link != "https://cert.europa.eu/publications/security-advisories/2026-021/" || it.Published.IsZero() ||
		!reflect.DeepEqual(it.CVEs, []string{"CVE-2026-114938"}) {
		t.Fatalf("item: %+v", it)
	}
}
