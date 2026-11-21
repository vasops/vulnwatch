package finding

import (
	"slices"
	"testing"
	"time"
)

func TestDedup(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(48 * time.Hour)
	tests := []struct {
		name    string
		in      []Finding
		wantIDs []string
		check   func(t *testing.T, out []Finding)
	}{
		{
			name: "same CVE from three sources merges",
			in: []Finding{
				{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Product: "argocd", Title: "ghsa title", Sources: []string{"ghsa"}, Fixed: []string{"3.1.8"}, Modified: t1},
				{ID: "CVE-2026-0001", Product: "argocd", Title: "nvd title", CVSS: 9.1, CVSSVector: "CVSS:3.1/AV:N", Sources: []string{"nvd"}, Published: t1, Modified: t2, MatchNote: "note"},
				{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Product: "argocd", Sources: []string{"osv"}, Fixed: []string{"3.0.15", "3.1.8"}},
			},
			wantIDs: []string{"CVE-2026-0001"},
			check: func(t *testing.T, out []Finding) {
				f := out[0]
				if f.Title != "ghsa title" {
					t.Errorf("title precedence: %q", f.Title)
				}
				if f.CVSS != 9.1 || f.Severity != SeverityCritical {
					t.Errorf("cvss/severity: %v %v", f.CVSS, f.Severity)
				}
				if !slices.Equal(f.Sources, []string{"ghsa", "nvd", "osv"}) {
					t.Errorf("sources: %v", f.Sources)
				}
				if !slices.Equal(f.Aliases, []string{"GHSA-aaaa-bbbb-cccc"}) {
					t.Errorf("aliases: %v", f.Aliases)
				}
				if len(f.Fixed) != 2 || !f.Modified.Equal(t2) || !f.Published.Equal(t1) || f.MatchNote != "note" {
					t.Errorf("merge: %+v", f)
				}
			},
		},
		{
			name: "transitive alias chain",
			in: []Finding{
				{ID: "GHSA-1", Aliases: []string{"PYSEC-1"}, Product: "litellm", Sources: []string{"ghsa"}},
				{ID: "PYSEC-1", Aliases: []string{"CVE-2026-9"}, Product: "litellm", Sources: []string{"osv"}},
				{ID: "CVE-2026-9", Product: "litellm", Sources: []string{"nvd"}},
			},
			wantIDs: []string{"CVE-2026-9"},
		},
		{
			name: "different products stay separate",
			in: []Finding{
				{ID: "CVE-2026-5", Product: "kubernetes", Sources: []string{"kubernetes_cve_feed"}},
				{ID: "CVE-2026-5", Product: "rke2", Sources: []string{"kubernetes_cve_feed"}},
			},
			wantIDs: []string{"CVE-2026-5", "CVE-2026-5"},
		},
		{
			name: "related IDs do not merge",
			in: []Finding{
				{ID: "https://example.invalid/release", Related: []string{"CVE-2026-1", "CVE-2026-2"}, Product: "gitlab-ce", Sources: []string{"rss"}},
				{ID: "CVE-2026-1", Product: "gitlab-ce", Sources: []string{"nvd"}},
				{ID: "CVE-2026-2", Product: "gitlab-ce", Sources: []string{"nvd"}},
			},
			wantIDs: []string{"CVE-2026-1", "CVE-2026-2", "https://example.invalid/release"},
		},
		{
			name: "CNA record before NVD, SSVC kept",
			in: []Finding{
				{ID: "CVE-2026-7", Product: "httpd", CVSS: 7.5, Sources: []string{"nvd"}, SSVCExploitation: "none"},
				{ID: "CVE-2026-7", Product: "httpd", CVSS: 9.8, Sources: []string{"cvelist"}, SSVCExploitation: "poc", SSVCAutomatable: "yes", SSVCTechnicalImpact: "total"},
				{ID: "CVE-2026-7", Product: "httpd", Sources: []string{"osv"}, SSVCExploitation: "active", SSVCAutomatable: "no"},
			},
			wantIDs: []string{"CVE-2026-7"},
			check: func(t *testing.T, out []Finding) {
				f := out[0]
				if f.CVSS != 9.8 {
					t.Errorf("cvss precedence: %v", f.CVSS)
				}
				if f.SSVCExploitation != "active" || f.SSVCAutomatable != "yes" || f.SSVCTechnicalImpact != "total" {
					t.Errorf("ssvc: %q %q %q", f.SSVCExploitation, f.SSVCAutomatable, f.SSVCTechnicalImpact)
				}
			},
		},
		{
			name: "GHSA without CVE keeps GHSA id",
			in: []Finding{
				{ID: "GHSA-zzzz", Product: "openbao", Severity: "high", Sources: []string{"ghsa"}},
			},
			wantIDs: []string{"GHSA-zzzz"},
			check: func(t *testing.T, out []Finding) {
				if out[0].Severity != SeverityHigh {
					t.Errorf("severity: %v", out[0].Severity)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.in {
				tt.in[i].Canonicalize()
			}
			out := Dedup(tt.in)
			var ids []string
			for _, f := range out {
				ids = append(ids, f.ID)
			}
			if !slices.Equal(ids, tt.wantIDs) {
				t.Fatalf("ids = %v, want %v", ids, tt.wantIDs)
			}
			if tt.check != nil {
				tt.check(t, out)
			}
		})
	}
}

func TestTagSource(t *testing.T) {
	nvd := Finding{ID: "CVE-2026-1", Product: "envoy", Sources: []string{"nvd"},
		Affected: []Range{{Fixed: "1.36.10"}, {}}, AffectedVersions: []string{"1.37.0", "1.37.0"}}
	nvd.TagSource()
	want := []Range{
		{Fixed: "1.36.10", Source: "nvd"},
		{Source: "nvd"},
		{Introduced: "1.37.0", LastAffected: "1.37.0", Exact: true, Source: "nvd"},
	}
	if !slices.Equal(nvd.Affected, want) || nvd.AffectedVersions != nil {
		t.Fatalf("tagged: %+v %v", nvd.Affected, nvd.AffectedVersions)
	}
	if !nvd.HasVersionData() || !nvd.Affected[1].AllVersions() || nvd.Affected[2].String() != "1.37.0" {
		t.Fatalf("tagged ranges keep their meaning: %+v", nvd.Affected)
	}

	ghsa := Finding{ID: "CVE-2026-1", Product: "envoy", Sources: []string{"ghsa"}, Affected: []Range{{Introduced: "1.18.0", Fixed: "1.40.0"}, {Fixed: "1.36.10"}}}
	ghsa.TagSource()
	out := Dedup([]Finding{nvd, ghsa})
	if len(out) != 1 || len(out[0].Affected) != 5 {
		t.Fatalf("the same range from two sources stays once per source: %+v", out)
	}
	out[0].TagSource()
	if out[0].Affected[0].Source != "ghsa" || out[0].Affected[2].Source != "nvd" {
		t.Fatalf("a merged finding keeps its tags: %+v", out[0].Affected)
	}

	all := Finding{Sources: []string{"nvd"}, Affected: []Range{{}}}
	if all.HasVersionData() {
		t.Fatal("all versions is no data")
	}
}

func TestChanges(t *testing.T) {
	base := Snapshot{Severity: SeverityHigh, CVSS: 7.5, Fixed: []string{"1.2.3"}, Match: "unknown"}
	tests := []struct {
		name string
		mod  func(s Snapshot) Snapshot
		want int
	}{
		{"identical", func(s Snapshot) Snapshot { return s }, 0},
		{"severity raised", func(s Snapshot) Snapshot { s.Severity = SeverityCritical; return s }, 1},
		{"severity lowered is not material", func(s Snapshot) Snapshot { s.Severity = SeverityMedium; return s }, 0},
		{"cvss nudge same severity", func(s Snapshot) Snapshot { s.CVSS = 7.8; return s }, 0},
		{"added to KEV", func(s Snapshot) Snapshot { s.KEV = true; return s }, 1},
		{"new fixed version", func(s Snapshot) Snapshot { s.Fixed = []string{"1.2.3", "1.3.0"}; return s }, 1},
		{"fixed version removed", func(s Snapshot) Snapshot { s.Fixed = nil; return s }, 0},
		{"match changed", func(s Snapshot) Snapshot { s.Match = "affected"; return s }, 1},
		{"several", func(s Snapshot) Snapshot { s.KEV = true; s.Match = "affected"; return s }, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Changes(base, tt.mod(base))
			if len(got) != tt.want {
				t.Fatalf("got %v, want %d changes", got, tt.want)
			}
		})
	}
}

func TestSnapshotHashStable(t *testing.T) {
	a := Finding{Severity: "high", Fixed: []string{"2.0", "1.0"}}
	b := Finding{Severity: "high", Fixed: []string{"1.0", "2.0"}}
	if a.Snapshot().Hash() != b.Snapshot().Hash() {
		t.Fatal("hash depends on fixed order")
	}
}

func TestPackageBrief(t *testing.T) {
	tests := []struct {
		image, name, brief string
	}{
		{"quay.io/argoproj/argocd:v3.5.6", "argocd:v3.5.6", "libssl3 3.0.1 (fixed in 3.0.2) in argocd:v3.5.6"},
		{"registry.acme.internal:5000/team-x/prod/keycloak:26.1@sha256:abc", "keycloak:26.1", "libssl3 3.0.1 (fixed in 3.0.2) in keycloak:26.1"},
		{"postgres:17.4", "postgres:17.4", "libssl3 3.0.1 (fixed in 3.0.2) in postgres:17.4"},
		{"ghcr.io/x/y@sha256:abc", "y", "libssl3 3.0.1 (fixed in 3.0.2) in y"},
		{"", "", "libssl3 3.0.1 (fixed in 3.0.2) in "},
	}
	for _, tt := range tests {
		p := Package{Image: tt.image, Name: "libssl3", Installed: "3.0.1", Fixed: "3.0.2"}
		if got := p.ImageName(); got != tt.name {
			t.Errorf("%s: name %q, want %q", tt.image, got, tt.name)
		}
		if got := p.Brief(); got != tt.brief {
			t.Errorf("%s: brief %q, want %q", tt.image, got, tt.brief)
		}
	}
}

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("Fixes cve-2026-1234 and CVE-2026-56789, again CVE-2026-1234")
	if !slices.Equal(got, []string{"CVE-2026-1234", "CVE-2026-56789"}) {
		t.Fatal(got)
	}
}
