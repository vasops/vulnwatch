package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

// Slack rejects a section over 3000 characters (invalid_blocks), and the
// run then repeats the rejected post every day (#4). Every finding is its
// own section, ten at most, the rest counted in "+N more".
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
	blocks := (*msgs)[0].Blocks
	// header, counts, ten findings, "+2 more", tail, context
	if len(blocks) != 15 {
		t.Fatalf("%d blocks", len(blocks))
	}
	var all []string
	for _, b := range blocks[1:] {
		if txt, ok := b["text"].(map[string]any); ok {
			section := txt["text"].(string)
			if n := utf8.RuneCountInString(section); n > maxSectionText {
				t.Fatalf("section is %d characters", n)
			}
			if strings.Count(section, "<") != strings.Count(section, ">") {
				t.Errorf("unbalanced link markup:\n%s", section)
			}
			all = append(all, section)
		}
	}
	text := strings.Join(all, "\n")
	if n := strings.Count(text, "*<https://example.invalid/advisories/"); n != maxSummaryItems {
		t.Errorf("listed %d findings:\n%s", n, text)
	}
	for _, want := range []string{"_+2 more on the dashboard_", "*Open:* 12 (new 12)", "|:bar_chart: Open the dashboard>"} {
		if !strings.Contains(text, want) {
			t.Errorf("summary lacks %q:\n%s", want, text)
		}
	}

	// A low max_section_text is honored too.
	for _, b := range summaryBlocks(rep, "", "", p1Count{}, "CALERT", nil, 500) {
		if sec, ok := b.(*slack.SectionBlock); ok && utf8.RuneCountInString(sec.Text.Text) > 500 {
			t.Errorf("section over 500:\n%s", sec.Text.Text)
		}
	}
}
