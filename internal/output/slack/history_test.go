package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

// withHistory adds n P1 findings of a full-history check to the sample.
func withHistory(n int) report.Report {
	rep := reporttest.Sample()
	for i := range n {
		rep.Open = append(rep.Open, report.OpenItem{
			ID: fmt.Sprintf("CVE-2024-%04d", i), Product: "keycloak", Constraint: "26.x", Title: "old", Severity: "critical",
			KEV: i == 0, Match: "affected", Priority: "P1", Fixed: []string{"26.0.9"}, FirstSeen: true,
		})
	}
	return rep
}

// A new tenant or a lost state must not post one card per historic P1 (#21).
func TestManyHistoryP1sShareOneCard(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	rep := withHistory(maxHistoryCards + 2)
	// One advisory in two tenants: one line naming both.
	for i, tenant := range []string{"acme", "beta"} {
		it := &rep.Open[len(rep.Open)-2+i]
		it.ID, it.Tenant, it.Environment, it.Scope = "CVE-2024-0005", tenant, "prod", tenant+"/prod"
	}
	if err := newOutput(t, srv.URL, "CALERT", "").Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	m := *msgs
	// Summary, the new P1's own card, one card for the 6 history findings.
	if len(m) != 3 {
		t.Fatalf("%d messages", len(m))
	}
	// The new P1 and the six history findings (one is in two tenants).
	if sum := blockText(m[0].Blocks); !strings.Contains(sum, ":rotating_light: *7 critical (P1) findings*") {
		t.Errorf("summary:\n%s", sum)
	}
	if !strings.Contains(blockText(m[1].Blocks), "CVE-2026-1001") {
		t.Errorf("new P1 card:\n%s", blockText(m[1].Blocks))
	}
	got := blockText(m[2].Blocks)
	if m[2].Text != "P1: 6 P1 findings from the full-history check" || m[2].Channel != "CALERT" {
		t.Errorf("grouped card: %q to %s", m[2].Text, m[2].Channel)
	}
	for _, want := range []string{
		":rotating_light: 6 P1 findings from the full-history check",
		":red_circle: *CVE-2024-0000* · *keycloak* `26.x` · :warning: KEV",
		"      ↳ Upgrade to a fixed version: 26.0.9.",
		":red_circle: *CVE-2024-0004* · *keycloak* `26.x`",
		":red_circle: *CVE-2024-0005* · *keycloak*\n      ↳ Upgrade to a fixed version: 26.0.9.\n      • acme: prod; beta: prod · `26.x`",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("grouped card lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "CVE-2024-0005") != 1 || strings.Contains(got, "CVE-2026-0900") {
		t.Errorf("grouped card:\n%s", got)
	}
}

func TestHistoryCardFitsSlackLimit(t *testing.T) {
	a := p1Alerts(withHistory(80))
	b := a[len(a)-1].blocks("", maxSectionText)
	section := b[1].(*slack.SectionBlock).Text.Text
	if n := len([]rune(section)); n > maxSectionText || !strings.Contains(section, "more on the dashboard_") || a[len(a)-1].count != 80 {
		t.Fatalf("%d characters:\n%s", n, section)
	}
}

func TestFewHistoryP1sKeepTheirCards(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	// The sample's still-open P1 is not first seen: exactly maxHistoryCards.
	if err := newOutput(t, srv.URL, "CALERT", "").Render(context.Background(), withHistory(maxHistoryCards)); err != nil {
		t.Fatal(err)
	}
	if len(*msgs) != 2+maxHistoryCards {
		t.Fatalf("%d messages", len(*msgs))
	}
}
