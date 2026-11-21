package cvelist

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
)

// doc is a CVE record with the given CNA container and ADP containers.
func doc(id, state, updated, cna string, adp ...string) string {
	return fmt.Sprintf(`{"dataType": "CVE_RECORD", "dataVersion": "5.2",
		"cveMetadata": {"cveId": %q, "state": %q, "datePublished": "2026-11-01T10:00:00.000Z", "dateUpdated": %q},
		"containers": {"cna": %s, "adp": [%s]}}`, id, state, updated, cna, strings.Join(adp, ","))
}

func mustDecode(t *testing.T, s string) *record {
	t.Helper()
	r, err := decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fixture(t *testing.T, name string) *record {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	r, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var httpd = config.CatalogEntry{
	CVEList: []config.CVEListName{{Vendor: " apache software foundation", Product: "Apache HTTP Server"}},
	NVD:     []string{"cpe:2.3:a:apache:http_server"},
}

func TestToFindingRealRecords(t *testing.T) {
	f, ok := toFinding("httpd", fixture(t, "CVE-2026-119618.json"), newMatcher(httpd))
	if !ok {
		t.Fatal("CVE-2026-119618 not matched by name")
	}
	if f.ID != "CVE-2026-119618" || f.Title != "Apache HTTP Server: mod_http2: heap corruption and RCE in assign_headers" ||
		f.Severity != finding.SeverityCritical || f.CVSS != 0 || !slices.Equal(f.Sources, []string{Name}) ||
		f.Modified.Format(time.RFC3339) != "2026-11-12T09:30:48Z" || f.Published.Format(time.RFC3339) != "2026-11-11T14:54:08Z" {
		t.Fatalf("mapping: %+v", f)
	}
	if !slices.Equal(f.Affected, []finding.Range{{Introduced: "2.4.55", LastAffected: "2.4.70"}}) || len(f.Fixed) != 0 {
		t.Fatalf("ranges: %+v fixed %v", f.Affected, f.Fixed)
	}
	for v, want := range map[string]match.Status{"2.4.70": match.Affected, "2.4.71": match.NotAffected, "2.4.54": match.NotAffected} {
		c, _ := match.ParseConstraint(v)
		if got := match.Match(c, f.Affected, f.AffectedVersions).Status; got != want {
			t.Errorf("httpd %s: %s, want %s", v, got, want)
		}
	}

	xz := config.CatalogEntry{OSV: []config.OSVPackage{{Ecosystem: "Go", Package: "github.com/tukaani-project/xz"}}}
	f, ok = toFinding("xz", fixture(t, "CVE-2024-3094.json"), newMatcher(xz))
	if !ok {
		t.Fatal("CVE-2024-3094 not matched by collection URL")
	}
	if f.CVSS != 10 || f.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || f.Severity != finding.SeverityCritical {
		t.Fatalf("cvss: %v %q %s", f.CVSS, f.CVSSVector, f.Severity)
	}
	if !slices.Equal(f.AffectedVersions, []string{"5.6.0", "5.6.1"}) || len(f.Affected) != 0 {
		t.Fatalf("versions: %v %v", f.AffectedVersions, f.Affected)
	}
	if f.SSVCExploitation != "none" || f.SSVCAutomatable != "yes" || f.SSVCTechnicalImpact != "total" {
		t.Fatalf("ssvc: %q %q %q", f.SSVCExploitation, f.SSVCAutomatable, f.SSVCTechnicalImpact)
	}
	if f.Title == "" || !strings.HasPrefix(f.Description, "Malicious code was discovered") {
		t.Fatalf("text: %q / %.40q", f.Title, f.Description)
	}
}

func TestToFinding(t *testing.T) {
	const upd = "2026-11-12T09:00:00.000Z"
	cna := func(affected, extra string) string {
		return fmt.Sprintf(`{"providerMetadata": {"shortName": "apache"},
			"descriptions": [{"lang": "de", "value": "Nicht diese."}, {"lang": "en", "value": "A flaw in mod_x allows RCE. More text."}],
			"references": [{"url": "https://httpd.apache.org/security/"}],
			"affected": [%s] %s}`, affected, extra)
	}
	ours := func(versions string) string {
		return `{"vendor": "Apache Software Foundation", "product": "Apache HTTP Server", "defaultStatus": "unaffected", "versions": [` + versions + `]}`
	}
	cisa := func(metrics string) string {
		return `{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [` + metrics + `]}`
	}
	ssvcMetric := `{"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "Active"}, {"Automatable": "no"}, {"Technical Impact": "partial"}], "version": "2.0.3"}}}`
	tests := []struct {
		name      string
		rec       string
		wantOK    bool
		ranges    []finding.Range
		versions  []string
		fixed     []string
		cvss      float64
		severity  string
		check     func(t *testing.T, f finding.Finding)
		entryName string
	}{
		{
			name:   "less than: range with a fix",
			rec:    doc("CVE-2026-1001", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "lessThan": "2.4.63", "status": "affected", "versionType": "semver"}`), "")),
			wantOK: true, ranges: []finding.Range{{Introduced: "2.4.0", Fixed: "2.4.63"}}, fixed: []string{"2.4.63"}, severity: finding.SeverityUnknown,
		},
		{
			name:   "less than or equal, from the beginning",
			rec:    doc("CVE-2026-1002", "PUBLISHED", upd, cna(ours(`{"version": "0", "lessThanOrEqual": "2.4.70", "status": "affected"}, {"version": "2.4.71", "status": "unaffected"}`), "")),
			wantOK: true, ranges: []finding.Range{{LastAffected: "2.4.70"}}, severity: finding.SeverityUnknown,
		},
		{
			name:   "exact versions",
			rec:    doc("CVE-2026-1003", "PUBLISHED", upd, cna(ours(`{"version": "2.4.60", "status": "affected"}, {"version": "2.4.61", "status": "affected"}`), "")),
			wantOK: true, versions: []string{"2.4.60", "2.4.61"}, severity: finding.SeverityUnknown,
		},
		{
			name:   "git commits: no version data",
			rec:    doc("CVE-2026-1004", "PUBLISHED", upd, cna(ours(`{"version": "1a2b3c4d", "lessThan": "5e6f7a8b", "status": "affected", "versionType": "git"}`), "")),
			wantOK: true, severity: finding.SeverityUnknown,
		},
		{
			name:   "one unparseable version: no version data rather than a partial answer",
			rec:    doc("CVE-2026-1005", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "lessThan": "2.4.63", "status": "affected"}, {"version": "trunk", "lessThan": "branch-x", "status": "affected"}`), "")),
			wantOK: true, severity: finding.SeverityUnknown,
		},
		{
			name: "affected by default: no version data",
			rec: doc("CVE-2026-1006", "PUBLISHED", upd, cna(`{"vendor": "Apache Software Foundation", "product": "Apache HTTP Server", "defaultStatus": "affected",
				"versions": [{"version": "2.4.0", "lessThan": "2.4.10", "status": "unaffected"}]}`, "")),
			wantOK: true, severity: finding.SeverityUnknown,
		},
		{
			name:   "rejected",
			rec:    doc("CVE-2026-1007", "REJECTED", upd, `{"providerMetadata": {"shortName": "apache"}, "rejectedReasons": [{"lang": "en", "value": "Duplicate."}]}`),
			wantOK: false,
		},
		{
			name:   "only another product of the record counts",
			rec:    doc("CVE-2026-1008", "PUBLISHED", upd, cna(`{"vendor": "Apache Software Foundation", "product": "Apache Tomcat", "versions": [{"version": "9.0", "lessThan": "9.0.99", "status": "affected"}]}`, "")),
			wantOK: false,
		},
		{
			name:   "every entry unaffected",
			rec:    doc("CVE-2026-1009", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "status": "unaffected"}`), "")),
			wantOK: false,
		},
		{
			name: "other products' ranges are not ours",
			rec: doc("CVE-2026-1010", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "lessThan": "2.4.63", "status": "affected"}`)+
				`, {"vendor": "Apache Software Foundation", "product": "mod_h2", "versions": [{"version": "2.0.8", "lessThanOrEqual": "2.0.42", "status": "affected"}]}`, "")),
			wantOK: true, ranges: []finding.Range{{Introduced: "2.4.0", Fixed: "2.4.63"}}, fixed: []string{"2.4.63"}, severity: finding.SeverityUnknown,
		},
		{
			name: "CNA CVSS before CISA's, newest CVSS version first",
			rec: doc("CVE-2026-1011", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "status": "affected"}`),
				`, "metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}, {"cvssV4_0": {"baseScore": 9.2, "baseSeverity": "CRITICAL", "vectorString": "CVSS:4.0/AV:N"}}]`),
				cisa(`{"cvssV3_1": {"baseScore": 5.3, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:L"}}`)),
			wantOK: true, versions: []string{"2.4.0"}, cvss: 9.2, severity: finding.SeverityCritical,
			check: func(t *testing.T, f finding.Finding) {
				if f.CVSSVector != "CVSS:4.0/AV:N" {
					t.Errorf("vector %q", f.CVSSVector)
				}
			},
		},
		{
			name: "CISA's CVSS and SSVC when the CNA has none",
			rec: doc("CVE-2026-1012", "PUBLISHED", upd, cna(ours(`{"version": "2.4.0", "status": "affected"}`), ""),
				`{"providerMetadata": {"shortName": "CVE"}, "metrics": [{"cvssV3_1": {"baseScore": 1.0, "baseSeverity": "LOW"}}]}`,
				cisa(`{"cvssV3_1": {"baseScore": 8.1, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:H"}}, `+ssvcMetric)),
			wantOK: true, versions: []string{"2.4.0"}, cvss: 8.1, severity: finding.SeverityHigh,
			check: func(t *testing.T, f finding.Finding) {
				if f.SSVCExploitation != "active" || f.SSVCAutomatable != "no" || f.SSVCTechnicalImpact != "partial" {
					t.Errorf("ssvc: %q %q %q", f.SSVCExploitation, f.SSVCAutomatable, f.SSVCTechnicalImpact)
				}
				if f.Title != "A flaw in mod_x allows RCE." || f.Description != "A flaw in mod_x allows RCE. More text." {
					t.Errorf("title %q, description %q", f.Title, f.Description)
				}
				if !slices.Equal(f.References, []string{"https://httpd.apache.org/security/"}) {
					t.Errorf("references %v", f.References)
				}
			},
		},
		{
			name: "matched by a CISA CPE (CPE 2.2 URI from the CNA too)",
			rec: doc("CVE-2026-1013", "PUBLISHED", upd, cna(`{"vendor": "apache", "product": "httpd", "cpes": ["cpe:/a:apache:http_server:2.4"], "versions": [{"version": "2.4.1", "status": "affected"}]}`, ""),
				`{"providerMetadata": {"shortName": "CISA-ADP"}, "affected": [{"vendor": "apache", "product": "http_server", "cpes": ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"], "defaultStatus": "unknown", "versions": [{"version": "2.4.0", "lessThan": "2.4.5", "status": "affected", "versionType": "custom"}]}]}`),
			wantOK: true, ranges: []finding.Range{{Introduced: "2.4.0", Fixed: "2.4.5"}}, versions: []string{"2.4.1"}, fixed: []string{"2.4.5"}, severity: finding.SeverityUnknown,
		},
	}
	m := newMatcher(httpd)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := mustDecode(t, tt.rec)
			f, ok := toFinding("httpd", r, m)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v", ok)
			}
			if !ok {
				return
			}
			if !slices.Equal(f.Affected, tt.ranges) || !slices.Equal(f.AffectedVersions, tt.versions) || !slices.Equal(f.Fixed, tt.fixed) {
				t.Errorf("versions: ranges %+v versions %v fixed %v", f.Affected, f.AffectedVersions, f.Fixed)
			}
			if f.CVSS != tt.cvss || f.Severity != tt.severity {
				t.Errorf("cvss %v severity %q", f.CVSS, f.Severity)
			}
			if tt.check != nil {
				tt.check(t, f)
			}
		})
	}
}

func TestEntryKeys(t *testing.T) {
	r := fixture(t, "CVE-2024-3094.json")
	e := r.entry()
	for _, want := range []string{
		"pkg:xz", "pkg:github.com/tukaani-project/xz", "name:red hat\tred hat enterprise linux 9",
		"cpe:redhat:enterprise_linux", "pkg:access.redhat.com/downloads/content/package-browser",
	} {
		if !slices.Contains(e.Keys, want) {
			t.Errorf("missing key %q in %q", want, e.Keys)
		}
	}
	if e.ID != "CVE-2024-3094" || e.Updated.Format(time.RFC3339) != "2026-11-04T21:11:43Z" || e.Removed {
		t.Fatalf("entry: %+v", e)
	}
	rej := mustDecode(t, doc("CVE-2026-1007", "REJECTED", "2026-11-12T09:00:00Z", `{}`)).entry()
	if !rej.Removed || len(rej.Keys) != 0 {
		t.Fatalf("rejected: %+v", rej)
	}
	// Placeholder names are not keys (thousands of old records say n/a).
	na := mustDecode(t, doc("CVE-2001-0001", "PUBLISHED", "2024-08-01T00:00:00", `{"affected": [{"vendor": "n/a", "product": "n/a"}]}`)).entry()
	if len(na.Keys) != 0 || na.Updated.IsZero() {
		t.Fatalf("n/a entry: %+v", na)
	}
}

func TestMatcherKeys(t *testing.T) {
	m := newMatcher(config.CatalogEntry{
		CVEList: []config.CVEListName{{Vendor: "Apache Software Foundation", Product: "Apache HTTP Server"}},
		NVD:     []string{"cpe:2.3:a:apache:http_server", "cpe:2.3:a:*:*"},
		OSV:     []config.OSVPackage{{Ecosystem: "Go", Package: "github.com/foo/bar"}},
	})
	want := []string{"cpe:apache:http_server", "name:apache software foundation\tapache http server", "pkg:github.com/foo/bar"}
	if !slices.Equal(m.keys, want) {
		t.Fatalf("keys %q", m.keys)
	}
	if !newMatcher(config.CatalogEntry{RSS: []string{"https://example.invalid/feed"}}).empty() {
		t.Fatal("rss only: no keys")
	}
	if path("CVE-2026-119618") != "2026/119xxx/CVE-2026-119618.json" || path("CVE-2024-3094") != "2024/3xxx/CVE-2024-3094.json" {
		t.Fatal("record path")
	}
}

// CNAs often write the vendor as "n/a"; the catalog lists such pairs
// explicitly, so they must reach the index. A pair without a product can't
// name anything.
func TestNameKey(t *testing.T) {
	for _, tc := range []struct{ vendor, product, want string }{
		{"Apache Software Foundation", " Apache HTTP Server ", "name:apache software foundation\tapache http server"},
		{"n/a", "Keycloak", "name:n/a\tkeycloak"},
		{"[UNKNOWN]", "keycloak", "name:[unknown]\tkeycloak"},
		{"n/a", "n/a", ""},
		{"Keycloak", "n/a", ""},
		{"", "keycloak", ""},
	} {
		if got := nameKey(tc.vendor, tc.product); got != tc.want {
			t.Errorf("nameKey(%q, %q) = %q, want %q", tc.vendor, tc.product, got, tc.want)
		}
	}
}
