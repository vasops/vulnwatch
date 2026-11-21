package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

// Slack rejects a section over 3000 characters (invalid_blocks), and the
// run then repeats the rejected post every day (#4). Long findings are
// dropped whole and counted in "+N more".
func TestSummaryFitsSlackSectionLimit(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", dashboardTmpl)

	c, _ := match.ParseConstraint("26.7.0")
	p := catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high"}
	var es []report.Entry
	for i := range 12 {
		es = append(es, report.Entry{
			Finding: finding.Finding{ID: fmt.Sprintf("CVE-2026-%04d", i), Product: "keycloak", Title: strings.Repeat("long title words ", 8), Severity: "high", Match: "affected",
				References: []string{"https://example.invalid/advisories/" + strings.Repeat("path/", 30) + fmt.Sprint(i)}},
			Product: p,
			Triage: triage.Result{Relevant: "yes", Priority: "P2", Method: triage.MethodRules,
				Action: strings.Repeat("upgrade & restart the pods ", 8)},
			Change: strings.Repeat("fixed version released: 26.7.1 ", 3),
		})
	}
	now := time.Date(2026, 11, 6, 6, 0, 0, 0, time.UTC)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now, Products: []catalog.Product{p}}, es)
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	section := (*msgs)[0].Blocks[1]["text"].(map[string]any)["text"].(string)
	if n := utf8.RuneCountInString(section); n > maxSectionText {
		t.Fatalf("section is %d characters", n)
	}
	listed := strings.Count(section, "*<https://example.invalid/advisories/")
	if listed == 0 || listed >= maxSummaryItems {
		t.Fatalf("listed %d findings:\n%s", listed, section)
	}
	for _, want := range []string{fmt.Sprintf("_+%d more on the dashboard_", 12-listed), "*Open:* 12 (new 12)", "|:bar_chart: Open the dashboard>"} {
		if !strings.Contains(section, want) {
			t.Errorf("section lacks %q:\n%s", want, section)
		}
	}
	if strings.Count(section, "<") != strings.Count(section, ">") {
		t.Errorf("unbalanced link markup:\n%s", section)
	}

	// A low max_section_text is honored too.
	text := fitSummary([]string{"*New:* 12"}, groupItems(rep.Items()), []string{"*Open:* 12"}, 500)
	if utf8.RuneCountInString(text) > 500 || !strings.Contains(text, "*Open:* 12") || !strings.Contains(text, "more on the dashboard") {
		t.Fatalf("fit 500:\n%s", text)
	}
}
