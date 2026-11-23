package teams

import (
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestDashboardLinkFillsTemplate(t *testing.T) {
	got := dashboardLink("https://grafana.example/d/x?from={from}&to={to}")
	want := "https://grafana.example/d/x?from=now-30d&to=now"
	if got != want {
		t.Errorf("dashboardLink = %q, want %q", got, want)
	}
}

func TestDashboardLinkEmptyTemplateIsEmpty(t *testing.T) {
	if got := dashboardLink(""); got != "" {
		t.Errorf("dashboardLink(\"\") = %q, want \"\"", got)
	}
}

func TestTargetURLFallsBackToMainWhenAlertEmpty(t *testing.T) {
	if got := targetURL("https://main", ""); got != "https://main" {
		t.Errorf("targetURL = %q, want the main URL", got)
	}
}

func TestTargetURLPrefersAlertWhenSet(t *testing.T) {
	if got := targetURL("https://main", "https://alert"); got != "https://alert" {
		t.Errorf("targetURL = %q, want the alert URL", got)
	}
}

func TestAdvisoryLinkPrefersAdvisoryOverLinks(t *testing.T) {
	advisories := []report.Advisory{{Source: "NVD", ID: "CVE-2026-1001", URL: "https://nvd.example/CVE-2026-1001"}}
	got := advisoryLink(advisories, []string{"https://other.example/ref"})
	if got != "https://nvd.example/CVE-2026-1001" {
		t.Errorf("advisoryLink = %q, want the advisory URL", got)
	}
}

func TestAdvisoryLinkFallsBackToLinksWhenNoAdvisories(t *testing.T) {
	got := advisoryLink(nil, []string{"https://other.example/ref", "https://other.example/ref2"})
	if got != "https://other.example/ref" {
		t.Errorf("advisoryLink = %q, want the first reference", got)
	}
}

func TestAdvisoryLinkEmptyWhenNothingToLinkTo(t *testing.T) {
	if got := advisoryLink(nil, nil); got != "" {
		t.Errorf("advisoryLink = %q, want \"\"", got)
	}
}

func TestOpenItemLinkUsesAdvisoryThenLink(t *testing.T) {
	withAdvisory := report.OpenItem{Advisories: []report.Advisory{{URL: "https://nvd.example/CVE-2026-0900"}}, Link: "https://other.example/ref"}
	if got := openItemLink(withAdvisory); got != "https://nvd.example/CVE-2026-0900" {
		t.Errorf("openItemLink = %q, want the advisory URL", got)
	}
	withoutAdvisory := report.OpenItem{Link: "https://other.example/ref"}
	if got := openItemLink(withoutAdvisory); got != "https://other.example/ref" {
		t.Errorf("openItemLink = %q, want the Link field", got)
	}
}

// p1Items must collect the one new P1 finding of reporttest.Sample()
// (CVE-2026-1001); its open P1 (CVE-2026-0900) is not FirstSeen, so it must
// not appear (that finding was already alerted on in an earlier run).
func TestP1ItemsCollectsOnlyTheNewP1FromSample(t *testing.T) {
	rep := reporttest.Sample()
	items := p1Items(rep)
	if len(items) != 1 {
		t.Fatalf("p1Items returned %d items, want 1: %+v", len(items), items)
	}
	wantLink := rep.Items()[0].Advisories[0].URL
	it := items[0]
	if it.ID != "CVE-2026-1001" {
		t.Errorf("p1Items[0].ID = %q, want CVE-2026-1001", it.ID)
	}
	if it.Product != "keycloak" {
		t.Errorf("p1Items[0].Product = %q, want keycloak", it.Product)
	}
	if it.Link != wantLink {
		t.Errorf("p1Items[0].Link = %q, want %q", it.Link, wantLink)
	}
}

// Scenario (unit level): the run summary card names the total count and is
// wrapped in the attachment envelope a Workflows webhook expects.
func TestBuildSummaryCardShapeAndCount(t *testing.T) {
	m := buildSummaryCard(twoNonP1FindingsReport(), "")
	if m.Type != "message" {
		t.Errorf("Type = %q, want message", m.Type)
	}
	if len(m.Attachments) != 1 {
		t.Fatalf("want exactly one attachment: %+v", m.Attachments)
	}
	if ct := m.Attachments[0].ContentType; ct != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("contentType = %q, want the adaptive card content type", ct)
	}
	c := m.Attachments[0].Content
	if c.Type != "AdaptiveCard" {
		t.Errorf("card type = %q, want AdaptiveCard", c.Type)
	}
	// Teams renders schema 1.6 and older; a newer version would not render.
	if c.Version != "1.5" {
		t.Errorf("card version = %q, want 1.5", c.Version)
	}
	if !strings.Contains(textOf(m), "2") {
		t.Errorf("no text block mentions the count 2: %+v", c.Body)
	}
}

// Scenario (unit level): a P1 card has an Action.OpenUrl button to the
// finding's link, and names the fields the task requires (CVE, severity).
func TestBuildP1CardHasOpenUrlActionToLink(t *testing.T) {
	it := p1Item{
		ID: "CVE-2026-1001", Product: "keycloak", Constraint: "26.x", Severity: "critical",
		CVSS: 9.8, KEV: true, EPSS: 0.9, Fixed: []string{"26.1.4"}, Action: "Upgrade to 26.1.4 today.",
		Link: "https://nvd.example/CVE-2026-1001",
	}
	m := buildP1Card(it)
	actions := m.Attachments[0].Content.Actions
	if len(actions) == 0 {
		t.Fatalf("card has no actions: %+v", m)
	}
	if actions[0].Type != "Action.OpenUrl" {
		t.Errorf("actions[0].Type = %q, want Action.OpenUrl", actions[0].Type)
	}
	if actions[0].URL != it.Link {
		t.Errorf("actions[0].URL = %q, want %q", actions[0].URL, it.Link)
	}
	var sawID bool
	for _, f := range factsOf(m) {
		if f.Value == it.ID {
			sawID = true
		}
	}
	if !sawID {
		t.Errorf("card facts should include the CVE id %q: %+v", it.ID, m)
	}
}

// Without a link the card carries no button at all.
func TestBuildP1CardWithoutLinkHasNoAction(t *testing.T) {
	m := buildP1Card(p1Item{ID: "CVE-2026-1001", Product: "keycloak", Severity: "critical"})
	if got := m.Attachments[0].Content.Actions; len(got) != 0 {
		t.Errorf("want no actions without a link: %+v", got)
	}
}

// A P1 heading is coloured Attention: an Adaptive Card has no card-level
// accent colour, so the heading is what carries severity.
func TestBuildP1CardMarksTheHeadingAttention(t *testing.T) {
	m := buildP1Card(p1Item{ID: "CVE-2026-1001", Product: "keycloak", Severity: "critical"})
	body := m.Attachments[0].Content.Body
	if len(body) == 0 || body[0].Color != "Attention" {
		t.Errorf("first body element should be an Attention-coloured heading: %+v", body)
	}
}

// factsOf flattens every FactSet in the card body, for assertions that do
// not care which set a fact is in.
func factsOf(m message) []fact {
	var out []fact
	for _, e := range m.Attachments[0].Content.Body {
		out = append(out, e.Facts...)
	}
	return out
}

// textOf joins every TextBlock in the card body.
func textOf(m message) string {
	var b strings.Builder
	for _, e := range m.Attachments[0].Content.Body {
		if e.Type == "TextBlock" {
			b.WriteString(e.Text + " ")
		}
	}
	return b.String()
}
