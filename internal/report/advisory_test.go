package report_test

import (
	"reflect"
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestAdvisoryLinks(t *testing.T) {
	l := report.AdvisoryLinks{NVD: "https://nvd.example/{id}", GitHub: "https://gh.example/{id}"}
	got := l.For([]string{"GHSA-4gv3-mc9p-5wqc", "CVE-2026-18963", "BIT-keycloak-2026-18963", "CVE-2026-18963"})
	want := []report.Advisory{
		{Source: "NVD", ID: "CVE-2026-18963", URL: "https://nvd.example/CVE-2026-18963"},
		{Source: "GitHub", ID: "GHSA-4gv3-mc9p-5wqc", URL: "https://gh.example/GHSA-4gv3-mc9p-5wqc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if got := (report.AdvisoryLinks{GitHub: l.GitHub}).For([]string{"CVE-1", "GHSA-1"}); len(got) != 1 || got[0].Source != "GitHub" {
		t.Fatalf("no NVD template: %+v", got)
	}
	if line := report.AdvisoryLine(want); line != "NVD https://nvd.example/CVE-2026-18963 · GitHub https://gh.example/GHSA-4gv3-mc9p-5wqc" {
		t.Fatal(line)
	}
}

func TestBuildAdvisories(t *testing.T) {
	r := reporttest.Sample()
	it := r.Items()[0]
	if len(it.Advisories) != 2 || it.Advisories[0].Source != "NVD" || it.Advisories[1].ID != "GHSA-abcd-efgh-ijkl" {
		t.Fatalf("item advisories: %+v", it.Advisories)
	}
	for _, o := range r.Open {
		if len(o.Advisories) == 0 || o.Advisories[0].ID != o.ID {
			t.Fatalf("open advisories: %+v", o)
		}
	}
	if kc := r.Open[0]; kc.ID != "CVE-2026-0900" || len(kc.Advisories) != 2 {
		t.Fatalf("open item aliases give the GitHub link: %+v", kc)
	}
}

func TestAdvisoryLinksPreferRepositoryAdvisory(t *testing.T) {
	l := report.AdvisoryLinks{NVD: "https://nvd.nist.gov/vuln/detail/{id}", GitHub: "https://github.com/advisories/{id}"}
	refs := []string{"https://nvd.nist.gov/x", "https://github.com/BerriAI/litellm/security/advisories/ghsa-w4c7-34wj-hqm8"}
	got := l.For([]string{"CVE-2026-1", "GHSA-W4C7-34WJ-HQM8", "GHSA-other"}, refs...)
	want := []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2026-1",
		"https://github.com/BerriAI/litellm/security/advisories/ghsa-w4c7-34wj-hqm8",
		"https://github.com/advisories/GHSA-other",
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i].URL != want[i] {
			t.Errorf("link %d = %s, want %s", i, got[i].URL, want[i])
		}
	}
}
