package sources

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/finding"
)

func TestCapGoMajor(t *testing.T) {
	tests := []struct {
		eco, pkg string
		in, want finding.Range
	}{
		{"go", "github.com/argoproj/argo-cd/v2", finding.Range{Introduced: "2.1.0"}, finding.Range{Introduced: "2.1.0", Fixed: "3.0.0"}},
		{"Go", "github.com/argoproj/argo-cd/v3", finding.Range{Introduced: "3.0.0", Fixed: "3.1.0"}, finding.Range{Introduced: "3.0.0", Fixed: "3.1.0"}},
		{"Go", "github.com/grafana/grafana", finding.Range{Introduced: "8.0.0"}, finding.Range{Introduced: "8.0.0"}},
		{"PyPI", "foo/v2", finding.Range{}, finding.Range{}},
		// "introduced: 0" and no fix is every version: no data, not "every 3.x".
		{"Go", "go.etcd.io/etcd/v3", finding.Range{}, finding.Range{}},
	}
	for _, tt := range tests {
		if got := CapGoMajor(tt.eco, tt.pkg, tt.in); got != tt.want {
			t.Errorf("%s %s: got %+v want %+v", tt.eco, tt.pkg, got, tt.want)
		}
	}
}

func TestIsGoPseudoVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"0.0.0-20260714163218-90272575e5f5":   true,
		"v0.0.0-20260714163218-90272575e5f5":  true,
		"1.2.4-0.20260714163218-90272575e5f5": true,
		"2.6.3":                               false,
		"3.6.0-rc1":                           false,
	} {
		if IsGoPseudoVersion(v) != want {
			t.Errorf("%s: want %v", v, want)
		}
	}
}

func TestCleanFixed(t *testing.T) {
	// Harbor CVE-2025-32019 and GHSA-56j8-6qr5-cg75 as merged from GitHub and OSV.
	got := CleanFixed([]string{"2.12.4", "2.13.1", "2.12.4-rc1", "2.13.1-rc1", "2.4.0-rc1.0.20250421072404-a13a16383a41",
		"2.12.4-rc1+incompatible", "2.13.1-rc1+incompatible", "N/A", " ", "1.27.0-rc.3"})
	if strings.Join(got, ",") != "2.12.4,2.13.1,1.27.0-rc.3" {
		t.Fatalf("got %v", got)
	}
}

func TestSplitVersions(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"1.36.12 1.37.8 1.38.6 1.39.3", []string{"1.36.12", "1.37.8", "1.38.6", "1.39.3"}},
		{"1.5.13, 1.6.7,1.7.1", []string{"1.5.13", "1.6.7", "1.7.1"}},
		{">= 1.28.4", []string{">=1.28.4"}},
		{"  ", []string{}},
	}
	for _, tt := range tests {
		if got := SplitVersions(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q: got %q want %q", tt.in, got, tt.want)
		}
	}
	if got := CleanFixed(SplitVersions("1.36.12 1.37.8 1.38.6 1.39.3")); len(got) != 4 {
		t.Fatalf("space-separated patched versions: %v", got)
	}
	if got := CleanFixed([]string{"v2.13.9", "2.13.9", "10.4", "10.4.0", "1.30.4+rke2r1", "1.30.4+rke2r2"}); strings.Join(got, ",") != "v2.13.9,10.4,1.30.4+rke2r1,1.30.4+rke2r2" {
		t.Fatalf("one entry per version: %v", got)
	}
}

func TestRangesFromPatched(t *testing.T) {
	got := RangesFromPatched([]string{" 1.7.1", "1.5.13", "N/A", "1.6.7"})
	want := []finding.Range{{Fixed: "1.5.13"}, {Introduced: "1.6.0", Fixed: "1.6.7"}, {Introduced: "1.7.0", Fixed: "1.7.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if !AllVersions(" All ") || AllVersions(">= 1.0") {
		t.Fatal("AllVersions")
	}
}

func TestRangeInWords(t *testing.T) {
	if got := RangeInWords("RELEASE.2024-06-06T09-36-42Z and newer"); got != ">= RELEASE.2024-06-06T09-36-42Z" {
		t.Fatal(got)
	}
	if got := RangeInWords("< 1.2.3"); got != "< 1.2.3" {
		t.Fatal(got)
	}
}
