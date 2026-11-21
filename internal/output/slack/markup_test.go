package slack

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

func TestLinkToAcceptsOnlySafeHTTPS(t *testing.T) {
	for _, tc := range []struct{ url, want string }{
		{"https://example.invalid/a?b=1&c=2", "<https://example.invalid/a?b=1&c=2|x &amp; y>"},
		{"https://x.example/a|click><!channel>", "x &amp; y"},
		{"http://example.invalid/a", "x &amp; y"},
		{"javascript:alert(1)", "x &amp; y"},
		{"https://example.invalid/a b", "x &amp; y"},
		{"https://example.invalid/a\nb", "x &amp; y"},
		{"https://example.invalid/a\x7fb", "x &amp; y"},
		{"https:///nohost", "x &amp; y"},
		{"", "x &amp; y"},
	} {
		if got := linkTo(tc.url, "x & y"); got != tc.want {
			t.Errorf("linkTo(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

// Reproduces #38: a reference URL "…|click><!channel>" produced a live
// <!channel>, and advisory text went unescaped into the notification text.
func TestAdvisoryDataCannotInjectMarkup(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")
	c, _ := match.ParseConstraint("26.7.0")
	p := catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high"}
	now := time.Date(2026, 11, 6, 6, 0, 0, 0, time.UTC)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now, Products: []catalog.Product{p}},
		[]report.Entry{{
			Finding: finding.Finding{ID: "https://feed.example/item", Product: "keycloak", Title: "<!channel> & <@U123> pwned", Severity: "<!here>",
				Fixed: []string{"<!everyone>"}, Match: "affected", References: []string{"https://x.example/a|click><!channel>"}},
			Product: p,
			Triage:  triage.Result{Relevant: "yes", Priority: "P1", Method: triage.MethodRules, Summary: "<!subteam^S1>", Action: "<https://evil.example|click>"},
			Change:  "fixed version released: <!channel>",
		}})
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(*msgs) != 2 {
		t.Fatalf("%d messages", len(*msgs))
	}
	for _, m := range *msgs {
		// Headers are plain_text: Slack shows them verbatim.
		var parsed []map[string]any
		for _, b := range m.Blocks {
			if b["type"] != "header" {
				parsed = append(parsed, b)
			}
		}
		all := m.Text + "\n" + blockText(parsed)
		for _, bad := range []string{"<!", "<@", "<https://x.example", "<https://evil", "<https://feed"} {
			if strings.Contains(all, bad) {
				t.Errorf("markup %q injected:\n%s", bad, all)
			}
		}
	}
	if a := (*msgs)[1].Text; a != "P1: keycloak &lt;!channel&gt; &amp; &lt;@U123&gt; pwned" {
		t.Errorf("alert text %q", a)
	}
	// Escaped once, not twice.
	if card := blockText((*msgs)[1].Blocks); !strings.Contains(card, "updated: fixed version released: &lt;!channel&gt;") {
		t.Errorf("card:\n%s", card)
	}
}
