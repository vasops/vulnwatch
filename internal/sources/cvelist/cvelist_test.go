package cvelist

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/state"
)

// fakeGitHub serves the releases API (paged), release assets and raw records.
type fakeGitHub struct {
	srv *httptest.Server

	mu       sync.Mutex
	releases []fakeRelease // newest first
	assets   map[string][]byte
	records  map[string]string // by path below /records/
	hits     map[string]int    // by request path
	auth     []string          // Authorization headers seen
	fail     bool              // the releases API answers 500
}

type fakeRelease struct {
	tag    string
	assets []string
}

func newFake(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{assets: map[string][]byte{}, records: map[string]string{}, hits: map[string]int{}}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[r.URL.Path]++
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	switch {
	case r.URL.Path == "/releases":
		if f.fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		lo, hi := min((page-1)*per, len(f.releases)), min(page*per, len(f.releases))
		var out []map[string]any
		for _, rel := range f.releases[lo:hi] {
			var as []map[string]string
			for _, a := range rel.assets {
				as = append(as, map[string]string{"name": a, "browser_download_url": f.srv.URL + "/download/" + rel.tag + "/" + a})
			}
			out = append(out, map[string]any{"tag_name": rel.tag, "assets": as})
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(r.URL.Path, "/download/"):
		b, ok := f.assets[filepath.Base(r.URL.Path)]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	case strings.HasPrefix(r.URL.Path, "/records/"):
		s, ok := f.records[strings.TrimPrefix(r.URL.Path, "/records/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(s))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeGitHub) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// publish adds a release (newest first) with its assets.
func (f *fakeGitHub) publish(tag string, assets map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rel := fakeRelease{tag: tag}
	for _, name := range slices.Sorted(maps.Keys(assets)) {
		rel.assets = append(rel.assets, name)
		f.assets[name] = assets[name]
	}
	f.releases = append([]fakeRelease{rel}, f.releases...)
}

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[name]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dump is the full dump: a zip holding a zip of every record.
func dump(t *testing.T, records ...string) []byte {
	files := map[string]string{"cves/deltaLog.json": `[]`, "cves/2026/2xxx/CVE-2026-2006.json": `{"cveMetadata": `}
	for _, r := range records {
		files["cves/2026/2xxx/"+idOf(t, r)+".json"] = r
	}
	return zipOf(t, map[string]string{"cves.zip": string(zipOf(t, files))})
}

func delta(t *testing.T, records ...string) []byte {
	files := map[string]string{}
	for _, r := range records {
		files["deltaCves/"+idOf(t, r)+".json"] = r
	}
	return zipOf(t, files)
}

func idOf(t *testing.T, rec string) string { return mustDecode(t, rec).Metadata.ID }

func httpdRec(id, updated, lessThan string) string {
	return doc(id, "PUBLISHED", updated, `{"affected": [{"vendor": "Apache Software Foundation", "product": "Apache HTTP Server",
		"versions": [{"version": "2.4.0", "lessThan": "`+lessThan+`", "status": "affected"}]}]}`)
}

func xzRec(id, updated string) string {
	return doc(id, "PUBLISHED", updated, `{"affected": [{"packageName": "xz", "versions": [{"version": "5.6.0", "status": "affected"}]}]}`)
}

var (
	xzEntry  = config.CatalogEntry{OSV: []config.OSVPackage{{Ecosystem: "Debian", Package: "xz"}}}
	cpeRec   = doc("CVE-2026-2002", "PUBLISHED", "2026-10-01T00:00:00Z", `{"affected": [{"vendor": "apache", "product": "httpd", "cpes": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"], "versions": [{"version": "2.2.0", "lessThan": "2.2.34", "status": "affected"}]}]}`)
	rejected = func(id, updated string) string { return doc(id, "REJECTED", updated, `{}`) }
)

type testEnv struct {
	fake  *fakeGitHub
	store *state.Store
	path  string
	work  string
}

func newEnv(t *testing.T) *testEnv {
	ctx := context.Background()
	fx := &testEnv{fake: newFake(t), path: filepath.Join(t.TempDir(), "state.db"), work: filepath.Join(t.TempDir(), "cvelist")}
	var err error
	if fx.store, err = state.Open(ctx, fx.path, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fx.store.Close() })
	return fx
}

func (fx *testEnv) source(t *testing.T, index Index, now time.Time) *Source {
	t.Helper()
	cfg := config.CVEListSource{
		Enabled:     true,
		ReleasesURL: fx.fake.srv.URL + "/releases",
		RecordsURL:  fx.fake.srv.URL + "/records/",
		WorkDir:     fx.work,
		TokenEnv:    "GITHUB_TOKEN",
	}
	client := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second)}, "test", nil)
	s := New(cfg, client, func(string) string { return "secret-token" }, index, nil)
	s.now = func() time.Time { return now }
	t.Cleanup(func() { s.Close() })
	return s
}

func fetchIDs(t *testing.T, s *Source, e config.CatalogEntry, since time.Time) []finding.Finding {
	t.Helper()
	fs, err := s.Fetch(context.Background(), sources.Selector{Product: "p", Entry: e}, since)
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(fs, func(a, b finding.Finding) int { return strings.Compare(a.ID, b.ID) })
	return fs
}

func ids(fs []finding.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	fx := newEnv(t)
	f := fx.fake
	// 2026-11-11: the day's changes (not needed: the dump of the 12th has them).
	f.publish("cve_2026-11-11_at_end_of_day", map[string][]byte{"2026-11-11_delta_CVEs_at_end_of_day.zip": delta(t, httpdRec("CVE-2026-2001", "2026-11-11T08:00:00Z", "2.4.62"))})
	// 2026-11-12 05:00Z: the dump at midnight and the changes since.
	f.publish("cve_2026-11-12_0400Z", map[string][]byte{"2026-11-12_delta_CVEs_at_0400Z.zip": delta(t)})
	f.publish("cve_2026-11-12_0500Z", map[string][]byte{
		"2026-11-12_all_CVEs_at_midnight.zip.zip": dump(t,
			httpdRec("CVE-2026-2001", "2026-11-11T08:00:00Z", "2.4.63"),
			cpeRec,
			xzRec("CVE-2026-2003", "2026-09-01T00:00:00Z"),
			rejected("CVE-2026-2004", "2026-11-01T00:00:00Z"),
			doc("CVE-2026-2005", "PUBLISHED", "2026-11-01T00:00:00Z", `{"affected": [{"vendor": "Foo", "product": "Bar"}]}`),
		),
		"2026-11-12_delta_CVEs_at_0500Z.zip": delta(t,
			httpdRec("CVE-2026-2001", "2026-11-12T03:00:00Z", "2.4.64"),
			httpdRec("CVE-2026-2007", "2026-11-12T04:00:00Z", "2.4.64"),
		),
	})

	// First run: the index is built from the dump, then today's changes.
	s := fx.source(t, fx.store, time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC))
	var (
		wg          sync.WaitGroup
		httpdF, xzF []finding.Finding
		none        []finding.Finding
	)
	wg.Add(3)
	go func() { defer wg.Done(); httpdF = fetchIDs(t, s, httpd, time.Time{}) }()
	go func() { defer wg.Done(); xzF = fetchIDs(t, s, xzEntry, time.Time{}) }()
	go func() { defer wg.Done(); none = fetchIDs(t, s, config.CatalogEntry{RSS: []string{"x"}}, time.Time{}) }()
	wg.Wait()
	if got := ids(httpdF); !slices.Equal(got, []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2007"}) {
		t.Fatalf("httpd: %v", got)
	}
	if !slices.Equal(httpdF[0].Fixed, []string{"2.4.64"}) || httpdF[0].Modified.Format(time.RFC3339) != "2026-11-12T03:00:00Z" {
		t.Fatalf("not the newest copy: %+v", httpdF[0])
	}
	if got := ids(xzF); !slices.Equal(got, []string{"CVE-2026-2003"}) || none != nil {
		t.Fatalf("xz: %v, no keys: %v", got, none)
	}
	if n := f.count("/releases"); n != 1 {
		t.Fatalf("release list requested %d times", n)
	}
	if f.count("/download/cve_2026-11-11_at_end_of_day/2026-11-11_delta_CVEs_at_end_of_day.zip") != 0 ||
		f.count("/download/cve_2026-11-12_0400Z/2026-11-12_delta_CVEs_at_0400Z.zip") != 0 {
		t.Fatal("downloaded a delta the dump and the latest delta cover")
	}
	if n := len(f.hits) - 3; n != 0 { // releases, the dump and the latest delta
		t.Fatalf("unexpected requests: %v", f.hits)
	}
	if slices.ContainsFunc(f.auth, func(a string) bool { return a != "" }) {
		t.Fatal("the token went to a host that is not api.github.com")
	}
	if m, err := fx.store.CVEListMeta(ctx); err != nil || m != (state.CVEListMeta{Baseline: "2026-11-12", Applied: "2026-11-11"}) {
		t.Fatalf("meta %+v %v", m, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(fx.work, "*")); len(left) != 0 {
		t.Fatalf("work dir not cleaned: %v", left)
	}

	// Next day: the end-of-day changes of the 12th and today's so far; the
	// dump is not downloaded again.
	f.publish("cve_2026-11-13_0000Z", map[string][]byte{"2026-11-13_all_CVEs_at_midnight.zip.zip": []byte("not used")})
	f.publish("cve_2026-11-12_at_end_of_day", map[string][]byte{"2026-11-12_delta_CVEs_at_end_of_day.zip": delta(t,
		httpdRec("CVE-2026-2001", "2026-11-12T03:00:00Z", "2.4.64"),
		httpdRec("CVE-2026-2007", "2026-11-12T04:00:00Z", "2.4.64"),
		httpdRec("CVE-2026-2008", "2026-11-12T20:00:00Z", "2.4.65"),
		rejected("CVE-2026-2003", "2026-11-12T21:00:00Z"),
	)})
	f.publish("cve_2026-11-13_0500Z", map[string][]byte{
		"2026-11-13_all_CVEs_at_midnight.zip.zip": []byte("not used"),
		"2026-11-13_delta_CVEs_at_0500Z.zip":      delta(t, xzRec("CVE-2026-2009", "2026-11-13T02:00:00Z")),
	})
	f.records["2026/2xxx/CVE-2026-2002.json"] = cpeRec
	s = fx.source(t, fx.store, time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC))
	if got := ids(fetchIDs(t, s, httpd, time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC))); !slices.Equal(got, []string{"CVE-2026-2008"}) {
		t.Fatalf("httpd changes: %v", got)
	}
	if got := ids(fetchIDs(t, s, httpd, time.Time{})); !slices.Equal(got, []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2007", "CVE-2026-2008"}) {
		t.Fatalf("httpd history: %v", got)
	}
	if got := ids(fetchIDs(t, s, xzEntry, time.Time{})); !slices.Equal(got, []string{"CVE-2026-2009"}) {
		t.Fatalf("xz after the rejection: %v", got)
	}
	if n := f.count("/records/2026/2xxx/CVE-2026-2002.json"); n != 1 || len(f.records) != 1 {
		t.Fatalf("record requests: %d", n)
	}
	if f.count("/download/cve_2026-11-13_0500Z/2026-11-13_all_CVEs_at_midnight.zip.zip") != 0 {
		t.Fatal("dump downloaded again")
	}
	if m, _ := fx.store.CVEListMeta(ctx); m.Applied != "2026-11-12" {
		t.Fatalf("applied: %+v", m)
	}
	s.Close()

	// A read-only store (dry run): this run's changes count, the index stays.
	f.publish("cve_2026-11-13_0600Z", map[string][]byte{"2026-11-13_delta_CVEs_at_0600Z.zip": delta(t,
		xzRec("CVE-2026-2009", "2026-11-13T02:00:00Z"),
		httpdRec("CVE-2026-2010", "2026-11-13T05:30:00Z", "2.4.66"),
	)})
	ro, err := state.Open(ctx, fx.path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	s = fx.source(t, ro, time.Date(2026, 11, 13, 7, 0, 0, 0, time.UTC))
	if got := ids(fetchIDs(t, s, httpd, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))); !slices.Equal(got, []string{"CVE-2026-2010"}) {
		t.Fatalf("read-only changes: %v", got)
	}
	if hits, _ := fx.store.CVEListLookup(ctx, newMatcher(httpd).keys, time.Time{}); len(hits) != 4 {
		t.Fatalf("read-only run wrote the index: %v", hits)
	}
}

func TestFetchNeedsIndex(t *testing.T) {
	fx := newEnv(t)
	fx.fake.publish("cve_2026-11-12_0500Z", map[string][]byte{"2026-11-12_all_CVEs_at_midnight.zip.zip": dump(t)})
	ro, err := state.Open(context.Background(), filepath.Join(t.TempDir(), "missing.db"), true)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	s := fx.source(t, ro, time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC))
	if _, err := s.Fetch(context.Background(), sources.Selector{Entry: httpd}, time.Time{}); err == nil || !strings.Contains(err.Error(), "full CVE list") {
		t.Fatalf("read-only without index: %v", err)
	}
	if fx.fake.count("/download/cve_2026-11-12_0500Z/2026-11-12_all_CVEs_at_midnight.zip.zip") != 0 {
		t.Fatal("downloaded the dump for a read-only store")
	}
	s = fx.source(t, nil, time.Now())
	if _, err := s.Fetch(context.Background(), sources.Selector{Entry: httpd}, time.Time{}); err == nil {
		t.Fatal("no state DB")
	}
}

func TestFetchFailsTogether(t *testing.T) {
	fx := newEnv(t)
	fx.fake.fail = true
	s := fx.source(t, fx.store, time.Now())
	for _, e := range []config.CatalogEntry{httpd, xzEntry} {
		if _, err := s.Fetch(context.Background(), sources.Selector{Entry: e}, time.Time{}); err == nil || !strings.Contains(err.Error(), "list releases") {
			t.Fatalf("want the sync error, got %v", err)
		}
	}
	if n := fx.fake.count("/releases"); n != 1 {
		t.Fatalf("release list requested %d times", n)
	}
	if _, err := os.Stat(fx.work); err != nil {
		t.Fatalf("work dir: %v", err)
	}
}

func TestReleasesPaged(t *testing.T) {
	fx := newEnv(t)
	// Five days of hourly releases and end-of-day releases: 125, newest first.
	for d := 8; d <= 12; d++ {
		day := fmt.Sprintf("2026-11-%02d", d)
		if d > 8 {
			prev := fmt.Sprintf("2026-11-%02d", d-1)
			fx.fake.publish("cve_"+prev+"_at_end_of_day", map[string][]byte{prev + "_delta_CVEs_at_end_of_day.zip": nil})
		}
		for h := range 24 {
			fx.fake.publish(fmt.Sprintf("cve_%s_%02d00Z", day, h), map[string][]byte{fmt.Sprintf("%s_delta_CVEs_at_%02d00Z.zip", day, h): nil})
		}
	}
	s := fx.source(t, fx.store, time.Now())
	// Page 1 ends with the end-of-day release of the 8th: the 8th's hourly
	// releases are on page 2.
	f, err := s.releases(context.Background(), "2026-11-08")
	if err != nil {
		t.Fatal(err)
	}
	if n := fx.fake.count("/releases"); n != 2 {
		t.Fatalf("pages: %d", n)
	}
	if got := slices.Sorted(maps.Keys(f.endOfDay)); !slices.Equal(got, []string{"2026-11-08", "2026-11-09", "2026-11-10", "2026-11-11"}) {
		t.Fatalf("end of day: %v", got)
	}
	if h := f.hourly["2026-11-12"]; h.hour != 23 || f.lastDay() != "2026-11-12" {
		t.Fatalf("latest hourly: %+v", h)
	}
}
