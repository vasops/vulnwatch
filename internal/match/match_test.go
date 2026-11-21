package match

import (
	"testing"

	"github.com/vasops/vulnwatch/internal/finding"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"1.8.1", "1.8.1", false},
		{"v1.30.4+rke2r1", "1.30.4+rke2r1", false},
		{"release-2.1.0", "2.1.0", false},
		{"26.0.6.Final", "26.0.6", false},
		{"3.0.0-rc1", "3.0.0-rc1", false},
		{"1.2.3.Beta1", "1.2.3-Beta1", false},
		{"10.4", "10.4.0", false},
		{"RELEASE.2025-04-22T22-12-26Z", "2025.4.22.221226", false},
		{"RELEASE.2024-01-01T00-00-00Z", "2024.1.1.0", false},
		{"2018-05-16t23-35-33z", "2018.5.16.233533", false},
		{"1.4.2_37", "1.4.2.37", false},
		{"2026-04-08", "", true},
		{"not-a-version", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			v, err := ParseVersion(tt.in)
			if tt.err {
				if err == nil {
					t.Fatalf("want error, got %v", v)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want, _ := ParseVersion(tt.want)
			if !v.Equal(want) {
				t.Fatalf("got %s want %s", v, tt.want)
			}
		})
	}
}

func TestParseConstraint(t *testing.T) {
	tests := []struct {
		in  string
		err bool
		any bool
	}{
		{"*", false, true},
		{"", false, true},
		{"1.8.1", false, false},
		{"26.x", false, false},
		{"26.1.x", false, false},
		{"3.*", false, false},
		{">=10.4 <11", false, false},
		{">= 10.4, < 11", false, false},
		{"<2.0", false, false},
		{"=1.2.3", false, false},
		{">=11 <10", true, false},
		{"!=1.0", true, false},
		{"1.0 2.0", true, false},
		{"abc.x", true, false},
		{">=garbage", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			c, err := ParseConstraint(tt.in)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want err %v", err, tt.err)
			}
			if err == nil && c.Any() != tt.any {
				t.Fatalf("any = %v, want %v", c.Any(), tt.any)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	rng := func(intro, fixed, last string) finding.Range {
		return finding.Range{Introduced: intro, Fixed: fixed, LastAffected: last}
	}
	tests := []struct {
		name       string
		constraint string
		ranges     []finding.Range
		versions   []string
		want       Status
	}{
		{"any is unknown", "*", []finding.Range{rng("0", "2.0.0", "")}, nil, Unknown},
		{"no data", "1.8.1", nil, nil, Unknown},
		{"exact inside", "1.8.1", []finding.Range{rng("1.8.0", "1.8.2", "")}, nil, Affected},
		{"exact at fixed", "1.8.2", []finding.Range{rng("1.8.0", "1.8.2", "")}, nil, NotAffected},
		{"exact at introduced", "1.8.0", []finding.Range{rng("1.8.0", "1.8.2", "")}, nil, Affected},
		{"exact at last_affected", "1.8.5", []finding.Range{rng("", "", "1.8.5")}, nil, Affected},
		{"exact below", "1.7.9", []finding.Range{rng("1.8.0", "1.8.2", "")}, nil, NotAffected},
		{"exact second range", "2.1.0", []finding.Range{rng("1.0", "1.5", ""), rng("2.0", "2.2", "")}, nil, Affected},
		{"wildcard fully inside", "26.1.x", []finding.Range{rng("26.0.0", "26.3.0", "")}, nil, Affected},
		{"wildcard partial", "26.x", []finding.Range{rng("0", "26.1.4", "")}, nil, Unknown},
		{"wildcard disjoint", "26.x", []finding.Range{rng("0", "25.0.9", "")}, nil, NotAffected},
		{"wildcard ends at fixed", "25.x", []finding.Range{rng("0", "26.0.0", "")}, nil, Affected},
		{"range disjoint", ">=10.4 <11", []finding.Range{rng("11.0", "11.1.2", "")}, nil, NotAffected},
		{"range partial", ">=10.4 <11", []finding.Range{rng("10.0", "10.4.5", "")}, nil, Unknown},
		{"unbounded range is no data", ">=10.4 <11", []finding.Range{{}}, nil, Unknown},
		{"rke2 metadata", "1.30.4+rke2r1", []finding.Range{rng("1.30.0", "1.30.5", "")}, nil, Affected},
		{"rke2 metadata v prefix", "v1.30.4+rke2r1", []finding.Range{rng("v1.30.0", "v1.30.4+rke2r2", "")}, nil, Affected},
		{"minio release affected", "RELEASE.2025-04-22T22-12-26Z", []finding.Range{rng("RELEASE.2023-05-18T00-05-36Z", "RELEASE.2026-04-11T03-20-12Z", "")}, nil, Affected},
		{"minio release fixed", "RELEASE.2026-04-11T03-20-12Z", []finding.Range{rng("RELEASE.2023-05-18T00-05-36Z", "RELEASE.2026-04-11T03-20-12Z", "")}, nil, NotAffected},
		{"minio nvd spelling", "RELEASE.2018-05-16T23-35-32Z", []finding.Range{rng("", "2018-05-16t23-35-33z", "")}, nil, Affected},
		{"nvd date bound (litellm)", "1.108.3", []finding.Range{rng("", "", "2026-04-08")}, nil, Unknown},
		{"nvd date bound next to a real range", "1.108.3", []finding.Range{rng("", "", "2026-04-08"), rng("1.81.8", "1.83.10", "")}, nil, Unknown},
		{"java legacy update range", "21.0.x", []finding.Range{rng("", "", "1.4.2_40"), rng("1.7.0", "", "1.7.0.40")}, nil, NotAffected},
		{"minio same day later build", "RELEASE.2026-04-11T03-20-13Z", []finding.Range{rng("", "RELEASE.2026-04-11T03-20-12Z", "")}, nil, NotAffected},
		{"union one affected", "13.0.5 || 13.2.4", []finding.Range{rng("13.0.0", "13.1.0", "")}, nil, Affected},
		{"union none affected", "13.0.5 || 13.2.4", []finding.Range{rng("12.0.0", "13.0.0", "")}, nil, NotAffected},
		{"union partial", "13.x || 14.0.1", []finding.Range{rng("13.0.0", "13.1.0", "")}, nil, Unknown},
		{"explicit version exact", "1.2.3", nil, []string{"1.2.2", "1.2.3"}, Affected},
		{"explicit version not listed", "1.2.4", nil, []string{"1.2.2", "1.2.3"}, NotAffected},
		{"explicit version in wildcard", "1.2.x", nil, []string{"1.2.3"}, Unknown},
		{"all versions next to a real range", "26.7.5", []finding.Range{{}, rng("", "24.0.0", "")}, nil, NotAffected},
		{"all versions alone is no data", "26.7.5", []finding.Range{{}}, nil, Unknown},
		{"open-ended next to bounded (envoy)", "1.36.6", []finding.Range{{Introduced: "1.28.0"}, rng("1.28.0", "1.28.4", ""), rng("1.30.0", "1.30.2", "")}, nil, NotAffected},
		{"Go database quirk next to NVD (vault)", "2.0.3", []finding.Range{{Introduced: "0.11.2"}, rng("0.11.2", "2.0.0", ""), rng("1.21.0", "1.21.5", "")}, nil, NotAffected},
		{"open-ended alone still counts", "2.0.3", []finding.Range{{Introduced: "0.11.2"}}, nil, Affected},
		{"junk range next to clean ones (harbor)", "2.15.1", []finding.Range{{Introduced: "1.9.*", LastAffected: "1.9.*"}, rng("1.7.0", "1.8.6", "")}, nil, Unknown},
		{"junk range next to a matching one", "1.8.0", []finding.Range{{Introduced: "1.9.*", LastAffected: "1.9.*"}, rng("1.7.0", "1.8.6", "")}, nil, Affected},
		{"junk range may cover the version", "1.9.4", []finding.Range{rng("1.0", "1.5", ""), rng("1.9.*", "1.9.5", "")}, nil, Unknown},
		{"open-ended on a later line stays", "2.3.0", []finding.Range{rng("1.0.0", "1.5.0", ""), {Introduced: "2.0.0"}}, nil, Affected},
		{"open-ended on a later line, older line fixed", "1.5.0", []finding.Range{rng("1.0.0", "1.5.0", ""), {Introduced: "2.0.0"}}, nil, NotAffected},
		{"open-ended before a later bounded line", "1.5.0", []finding.Range{{Introduced: "1.0.0"}, rng("2.0.0", "2.4.0", "")}, nil, Affected},
		{"open-ended with same start dropped", "1.28.2", []finding.Range{{Introduced: "1.28.0"}, rng("1.28.0", "1.28.4", "")}, nil, Affected},
		{"open-ended with same start dropped, fixed", "1.28.5", []finding.Range{{Introduced: "1.28.0"}, rng("1.28.0", "1.28.4", "")}, nil, NotAffected},
		{"open-ended start covered by bounded", "1.28.5", []finding.Range{{Introduced: "1.28.2"}, rng("1.28.0", "1.28.4", "")}, nil, NotAffected},
		{"platform only", "7.5.0", []finding.Range{{Fixed: "8.0.0", Platform: "windows"}}, nil, Unknown},
		{"platform only, outside", "8.1.0", []finding.Range{{Fixed: "8.0.0", Platform: "windows"}}, nil, NotAffected},
		{"platform and plain range", "7.5.0", []finding.Range{{Fixed: "8.0.0", Platform: "windows"}, rng("7.0.0", "7.6.0", "")}, nil, Affected},
		{"osv events <1.5.0 then >=2.0.0", "2.3.0", []finding.Range{rng("", "1.5.0", ""), {Introduced: "2.0.0"}}, nil, Affected},
		{"junk range alone", "2.15.1", []finding.Range{{Introduced: "branch", LastAffected: "branch"}}, nil, Unknown},
		{"junk tags in a version list", "26.7.5", []finding.Range{rng("", "21.1.2", "")}, []string{"not a version", "20.0.3"}, NotAffected},
		{"only junk tags", "26.7.5", nil, []string{"not a version"}, Unknown},
		{"unparseable only", "1.2.3", []finding.Range{rng("abc", "def", "")}, nil, Unknown},
		{"exclusive introduced", "1.0.0", []finding.Range{{Introduced: "1.0.0", IntroducedExclusive: true, Fixed: "2.0"}}, nil, NotAffected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseConstraint(tt.constraint)
			if err != nil {
				t.Fatal(err)
			}
			got := Match(c, tt.ranges, tt.versions)
			if got.Status != tt.want {
				t.Fatalf("got %s (%s), want %s", got.Status, got.Detail, tt.want)
			}
		})
	}
}

func TestMatchPerSource(t *testing.T) {
	src := func(source string, r finding.Range) finding.Range {
		r.Source = source
		return r
	}
	exact := func(source, v string) finding.Range {
		return finding.Range{Introduced: v, LastAffected: v, Exact: true, Source: source}
	}
	// Issue #11: GHSA's coarse range next to NVD's per-branch ranges.
	envoy := []finding.Range{
		src("ghsa", finding.Range{Introduced: "1.18.0", Fixed: "1.40.0"}),
		src("nvd", finding.Range{Fixed: "1.36.10"}),
		src("nvd", finding.Range{Introduced: "1.37.0", Fixed: "1.37.6"}),
	}
	tests := []struct {
		name       string
		constraint string
		ranges     []finding.Range
		versions   []string
		want       Status
		detail     string // exact detail, when set
	}{
		{"#11 fixed in branch: sources disagree", "1.36.10", envoy, nil, Unknown,
			"sources disagree: ghsa: affected (>=1.18.0 <1.40.0); nvd: not affected"},
		{"#11 before the fix: both affected", "1.36.9", envoy, nil, Affected, "1.36.9 is within affected range >=1.18.0 <1.40.0"},
		{"#11 untagged keeps the old result", "1.36.10", []finding.Range{{Introduced: "1.18.0", Fixed: "1.40.0"}, {Fixed: "1.36.10"}}, nil, Affected, ""},
		{"agree not affected", "1.40.1", envoy, nil, NotAffected, "1.40.1 is outside all affected ranges"},
		{"agree affected", "1.37.2", envoy, nil, Affected, ""},
		{"agree unknown", "1.x", envoy, nil, Unknown, "1.x partially overlaps affected >=1.18.0 <1.40.0; depends on the exact deployed version"},
		{"partial against affected disagrees", "1.36.x", []finding.Range{src("ghsa", finding.Range{Introduced: "1.18.0", Fixed: "1.40.0"}), src("nvd", finding.Range{Fixed: "1.36.10"})}, nil, Unknown,
			"sources disagree: ghsa: affected (>=1.18.0 <1.40.0); nvd: unknown (1.36.x partially overlaps affected <1.36.10; depends on the exact deployed version)"},
		{"source without data ignored", "1.36.10", []finding.Range{src("nvd", finding.Range{}), src("ghsa", finding.Range{Fixed: "1.36.10"})}, nil, NotAffected, ""},
		{"only sources without data", "1.36.10", []finding.Range{src("nvd", finding.Range{}), src("cvelist", finding.Range{})}, nil, Unknown, "source provides no affected version data"},
		{"open range superseded by another source (vault)", "2.0.3", []finding.Range{src("osv", finding.Range{Introduced: "0.11.2"}), src("nvd", finding.Range{Introduced: "0.11.2", Fixed: "2.0.0"}), src("nvd", finding.Range{Introduced: "1.21.0", Fixed: "1.21.5"})}, nil, NotAffected, ""},
		{"open range on another line disagrees", "2.3.0", []finding.Range{src("osv", finding.Range{Introduced: "2.0.0"}), src("nvd", finding.Range{Fixed: "1.5.0"})}, nil, Unknown,
			"sources disagree: nvd: not affected; osv: affected (>=2.0.0)"},
		{"exact versions per source agree", "1.2.3", []finding.Range{exact("nvd", "1.2.3"), src("osv", finding.Range{Introduced: "1.2.0", Fixed: "1.2.4"})}, nil, Affected, "1.2.3 is listed as an affected version"},
		{"exact version only one source lists", "1.2.3", []finding.Range{exact("nvd", "1.2.2"), exact("osv", "1.2.3")}, nil, Unknown,
			"sources disagree: nvd: not affected; osv: affected (1.2.3)"},
		{"junk tags of a source stay with it", "26.7.5", []finding.Range{exact("osv", "not a version"), exact("osv", "20.0.3"), src("nvd", finding.Range{Fixed: "21.1.2"})}, nil, NotAffected, ""},
		{"unparseable source disagrees", "2.15.1", []finding.Range{src("osv", finding.Range{Introduced: "1.9.*", LastAffected: "1.9.*"}), src("nvd", finding.Range{Introduced: "1.7.0", Fixed: "1.8.6"})}, nil, Unknown,
			"sources disagree: nvd: not affected; osv: unknown (affected range >=1.9.* <=1.9.* could not be parsed)"},
		{"platform-limited source", "7.5.0", []finding.Range{src("nvd", finding.Range{Fixed: "8.0.0", Platform: "windows"}), src("ghsa", finding.Range{Introduced: "7.0.0", Fixed: "7.6.0"})}, nil, Unknown, ""},
		{"platform-limited source, outside", "8.1.0", []finding.Range{src("nvd", finding.Range{Fixed: "8.0.0", Platform: "windows"}), src("ghsa", finding.Range{Introduced: "7.0.0", Fixed: "7.6.0"})}, nil, NotAffected, ""},
		{"platform and plain range of one source", "7.5.0", []finding.Range{src("nvd", finding.Range{Fixed: "8.0.0", Platform: "windows"}), src("nvd", finding.Range{Introduced: "7.0.0", Fixed: "7.6.0"})}, nil, Affected, ""},
		{"untagged versions next to tagged ranges", "1.2.3", []finding.Range{src("nvd", finding.Range{Fixed: "1.2.3"})}, []string{"1.2.3"}, Unknown,
			"sources disagree: unattributed: affected (1.2.3); nvd: not affected"},
		{"union: one deployed version disagrees", "1.36.10 || 1.36.9", envoy, nil, Affected, ""},
		{"union: disagreement is unknown", "1.36.10 || 1.40.1", envoy, nil, Unknown, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseConstraint(tt.constraint)
			if err != nil {
				t.Fatal(err)
			}
			got := Match(c, tt.ranges, tt.versions)
			if got.Status != tt.want || (tt.detail != "" && got.Detail != tt.detail) {
				t.Fatalf("got %s (%s), want %s (%s)", got.Status, got.Detail, tt.want, tt.detail)
			}
		})
	}
}

func TestParseRangeExpr(t *testing.T) {
	tests := []struct {
		in   string
		want finding.Range
	}{
		{">= 1.0.0, < 1.2.3", finding.Range{Introduced: "1.0.0", Fixed: "1.2.3"}},
		{"<= 2.0", finding.Range{LastAffected: "2.0"}},
		{"< 3.1.8", finding.Range{Fixed: "3.1.8"}},
		{"= 1.4.1", finding.Range{Introduced: "1.4.1", LastAffected: "1.4.1"}},
		{"> 1.0, <= 1.5", finding.Range{Introduced: "1.0", IntroducedExclusive: true, LastAffected: "1.5"}},
		{"> RELEASE.2024-03-30T09-41-56Z", finding.Range{Introduced: "RELEASE.2024-03-30T09-41-56Z", IntroducedExclusive: true}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseRangeExpr(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got %+v want %+v", got, tt.want)
			}
		})
	}
}

func TestUnion(t *testing.T) {
	if got := Union("13.0.5", "", "13.2.4 || 13.0.5"); got != "13.0.5 || 13.2.4" {
		t.Fatal(got)
	}
	if c, err := ParseConstraint("1.0 || *"); err != nil || !c.Any() {
		t.Fatalf("a union with * tracks everything: %v %v", c, err)
	}
	if _, err := ParseConstraint("1.0 ||"); err == nil {
		t.Fatal("empty alternative must fail")
	}
}

func TestUpgradeTarget(t *testing.T) {
	pg, _ := ParseConstraint("17.4")
	fixes := [][]string{
		{"14.21", "15.16", "16.12", "17.8", "18.2"},
		{"14.24", "15.19", "16.15", "17.11", "18.5"},
		{"17.11", "18.5"},
		nil,
	}
	if target, unfixed := UpgradeTarget(pg, fixes); target != "17.11" || unfixed != 1 {
		t.Fatalf("postgres: %q %d", target, unfixed)
	}
	kc, _ := ParseConstraint("26.7.0 || 20.0.3")
	alts := kc.Alternatives()
	f := [][]string{{"26.4.15", "26.6.6", "26.7.5"}, {"23.0.1"}}
	if target, _ := UpgradeTarget(alts[0], f); target != "26.7.5" {
		t.Fatalf("26.7.0: %q", target)
	}
	if target, _ := UpgradeTarget(alts[1], f); target != "26.4.15" {
		t.Fatalf("20.0.3: %q", target)
	}
	goC, _ := ParseConstraint("1.26.4")
	if target, _ := UpgradeTarget(goC, [][]string{{"1.25.13", "1.26.6", "1.27.0-rc.3"}, {"1.27.0-rc.3"}}); target != "1.27.0-rc.3" {
		t.Fatalf("go: %q", target)
	}
	if target, _ := UpgradeTarget(goC, [][]string{{"1.27.0-rc.3", "1.26.6"}}); target != "1.26.6" {
		t.Fatalf("release before pre-release: %q", target)
	}
}

func TestAllows(t *testing.T) {
	cases := []struct {
		constraint, version string
		want                bool
	}{
		{">=1.33.0", "1.34.2", true},
		{">=1.33.0", "v1.32.9", false},
		{"17.4", "17.4", true},
		{"17.4", "17.6", false},
		{"26.x", "26.7.0", true},
		{"20.0.3 || 26.7.0", "26.7.0", true},
		{"20.0.3 || 26.7.0", "26.7.5", false},
		{"v1.34.2+rke2r1", "v1.34.2+rke2r1", true},
		{"*", "anything", true},
		{"1.2.3", "latest", false},
	}
	for _, c := range cases {
		con, err := ParseConstraint(c.constraint)
		if err != nil {
			t.Fatal(err)
		}
		if got := con.Allows(c.version); got != c.want {
			t.Errorf("%q allows %q = %v, want %v", c.constraint, c.version, got, c.want)
		}
	}
}
