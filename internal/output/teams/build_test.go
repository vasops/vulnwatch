package teams

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

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

// The open P1 of Sample() is not FirstSeen: it was alerted on in an earlier run.
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

// The heading carries severity: a card has no card-level accent colour.
func TestBuildP1CardMarksTheHeadingAttention(t *testing.T) {
	m := buildP1Card(p1Item{ID: "CVE-2026-1001", Product: "keycloak", Severity: "critical"})
	body := m.Attachments[0].Content.Body
	if len(body) == 0 || body[0].Color != "Attention" {
		t.Errorf("first body element should be an Attention-coloured heading: %+v", body)
	}
}

func factsOf(m message) []fact {
	var out []fact
	for _, e := range m.Attachments[0].Content.Body {
		out = append(out, e.Facts...)
	}
	return out
}

func textOf(m message) string {
	var b strings.Builder
	for _, e := range m.Attachments[0].Content.Body {
		if e.Type == "TextBlock" {
			b.WriteString(e.Text + " ")
		}
	}
	return b.String()
}

func scoped(tenant, env, constraint, prio string) report.Item {
	return report.Item{
		ID: "CVE-2026-0001", Product: "debian-13-kernel", Tenant: tenant, Environment: env, Scope: tenant + "/" + env,
		Constraint: constraint, Priority: prio, Change: "new", Action: "Upgrade the kernel.", Severity: "critical",
		CVSS: 9.8, Fixed: []string{"6.12.113-1"}, Links: []string{"https://example.com/CVE-2026-0001"},
	}
}

func reportOf(items []report.Item, open ...report.OpenItem) report.Report {
	now := time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC)
	return report.Report{
		Mode: report.ModeRun, Since: now.Add(-24 * time.Hour), Until: now,
		Groups: []report.PriorityGroup{{Priority: "P1", Products: []report.ProductGroup{{Items: items}}}},
		Open:   open,
	}
}

// eightScopes is one finding in five version groups and eight scopes.
func eightScopes() []report.Item {
	return []report.Item{
		scoped("acme", "dev", "6.12.95", "P1"),
		scoped("globex", "test", "6.12.95", "P1"),
		scoped("acme", "prod", "6.12.95 || 6.12.101", "P1"),
		scoped("initech", "dev", "6.12.57", "P1"),
		scoped("initech", "stage", "6.12.57", "P1"),
		scoped("initech", "prod", "6.12.62", "P1"),
		scoped("umbrella", "prod", "6.12.88", "P1"),
		scoped("umbrella", "stage", "6.12.88", "P1"),
	}
}

func factTitles(fs []fact) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}

func factSets(m message) [][]fact {
	var out [][]fact
	for _, e := range m.Attachments[0].Content.Body {
		if e.Type == "FactSet" {
			out = append(out, e.Facts)
		}
	}
	return out
}

func TestP1CardOneFindingFiveVersionGroupsEightScopes(t *testing.T) {
	items := p1Items(reportOf(eightScopes()))
	if len(items) != 1 {
		t.Fatalf("p1Items = %d, want one card for the finding", len(items))
	}
	m := buildP1Card(items[0])
	body := m.Attachments[0].Content.Body
	if body[0].Text != "P1 · debian-13-kernel · CVE-2026-0001 · 8 environments" || body[0].Color != "Attention" {
		t.Errorf("heading = %+v", body[0])
	}
	sets := factSets(m)
	if len(sets) != 2 {
		t.Fatalf("fact sets = %d, want facts and Affected", len(sets))
	}
	want := []string{"CVE", "Product", "Severity", "CVSS", "KEV/EPSS", "Fixed in", "Action"}
	if got := factTitles(sets[0]); !reflect.DeepEqual(got, want) {
		t.Errorf("facts = %q, want %q (no Version)", got, want)
	}
	if sets[0][1].Value != "debian-13-kernel" {
		t.Errorf("Product = %q, want it without a scope", sets[0][1].Value)
	}
	if body[2].Type != "TextBlock" || body[2].Text != "Affected" || body[2].Weight != "Bolder" {
		t.Errorf("Affected text = %+v", body[2])
	}
	wantAff := []fact{
		{"6.12.95", "acme: dev; globex: test"},
		{"6.12.95, 6.12.101", "acme: prod"},
		{"6.12.57", "initech: dev, stage"},
		{"6.12.62", "initech: prod"},
		{"6.12.88", "umbrella: prod, stage"},
	}
	if !reflect.DeepEqual(sets[1], wantAff) {
		t.Errorf("Affected = %+v, want %+v", sets[1], wantAff)
	}
	if acts := m.Attachments[0].Content.Actions; len(acts) != 1 || acts[0].URL != "https://example.com/CVE-2026-0001" {
		t.Errorf("button = %+v", acts)
	}
}

func TestP1CardMixedPrioritiesListsOnlyTheP1Scope(t *testing.T) {
	items := p1Items(reportOf([]report.Item{
		scoped("acme", "dev", "6.12.95", "P2"),
		scoped("acme", "prod", "6.12.95", "P1"),
	}))
	if len(items) != 1 {
		t.Fatalf("p1Items = %d, want 1", len(items))
	}
	m := buildP1Card(items[0])
	if h := m.Attachments[0].Content.Body[0].Text; h != "P1 · acme/prod debian-13-kernel · CVE-2026-0001" {
		t.Errorf("heading = %q, want the one-scope form", h)
	}
	sets := factSets(m)
	if len(sets) != 1 {
		t.Fatalf("fact sets = %d, want 1 (no Affected)", len(sets))
	}
	var version string
	for _, f := range sets[0] {
		if f.Title == "Version" {
			version = f.Value
		}
	}
	if version != "6.12.95" {
		t.Errorf("Version = %q", version)
	}
	if strings.Contains(textOf(m), "Affected") {
		t.Errorf("one-scope card must not have an Affected text: %q", textOf(m))
	}
}

func TestP1CardMoreThanTwentyAffectedLines(t *testing.T) {
	var items []report.Item
	for i := 0; i < 25; i++ {
		items = append(items, scoped("acme", fmt.Sprintf("env%02d", i), fmt.Sprintf("6.12.%d", i), "P1"))
	}
	m := buildP1Card(p1Items(reportOf(items))[0])
	aff := factSets(m)[1]
	if len(aff) != 21 {
		t.Fatalf("Affected facts = %d, want 20 and one more", len(aff))
	}
	if aff[20].Title != "+5 more environments" {
		t.Errorf("last fact = %+v, want +5 more environments", aff[20])
	}
}

func TestP1CardOneMoreAffectedLineIsSingular(t *testing.T) {
	var items []report.Item
	for i := 0; i < 21; i++ {
		items = append(items, scoped("acme", fmt.Sprintf("env%02d", i), fmt.Sprintf("6.12.%d", i), "P1"))
	}
	aff := factSets(buildP1Card(p1Items(reportOf(items))[0]))[1]
	if last := aff[len(aff)-1]; last.Title != "+1 more environment" {
		t.Errorf("last fact = %+v, want +1 more environment", last)
	}
}

func TestP1CardSingleStackUnchanged(t *testing.T) {
	it := report.Item{
		ID: "CVE-2026-1001", Product: "keycloak", Constraint: "26.x", Priority: "P1", Severity: "critical",
		CVSS: 9.8, KEV: true, EPSS: 0.9, Fixed: []string{"26.1.4"}, Action: "Upgrade to 26.1.4 today.",
		Links: []string{"https://example.com/ref"},
	}
	items := p1Items(reportOf([]report.Item{it}))
	if len(items) != 1 {
		t.Fatalf("p1Items = %d, want 1", len(items))
	}
	m := buildP1Card(items[0])
	body := m.Attachments[0].Content.Body
	if len(body) != 2 || body[0].Text != "P1 · keycloak · CVE-2026-1001" {
		t.Fatalf("body = %+v", body)
	}
	want := []fact{
		{"CVE", "CVE-2026-1001"}, {"Product", "keycloak"}, {"Version", "26.x"}, {"Severity", "critical"},
		{"CVSS", "9.8"}, {"KEV/EPSS", "exploited in the wild (CISA KEV) · EPSS 90.0%"},
		{"Fixed in", "26.1.4"}, {"Action", "Upgrade to 26.1.4 today."},
	}
	if !reflect.DeepEqual(body[1].Facts, want) {
		t.Errorf("facts = %+v, want %+v", body[1].Facts, want)
	}
}

func TestP1ItemsFullHistoryFindingsOneCardPerFinding(t *testing.T) {
	open := func(tenant, env, constraint, id string) report.OpenItem {
		return report.OpenItem{
			ID: id, Product: "debian-13-kernel", Tenant: tenant, Environment: env, Scope: tenant + "/" + env,
			Constraint: constraint, Priority: "P1", FirstSeen: true, Fixed: []string{"6.12.113-1"},
		}
	}
	notNew := open("acme", "dev", "6.12.1", "CVE-2026-0003")
	notNew.FirstSeen = false
	items := p1Items(reportOf(nil,
		open("acme", "dev", "6.12.95", "CVE-2026-0002"),
		open("globex", "test", "6.12.57", "CVE-2026-0002"),
		open("initech", "prod", "6.12.62", "CVE-2026-0002"),
		open("acme", "prod", "6.12.95", "CVE-2026-0004"),
		open("globex", "prod", "6.12.95", "CVE-2026-0004"),
		notNew,
	))
	if len(items) != 2 {
		t.Fatalf("p1Items = %d, want 2 (one per finding, not first-seen skipped): %+v", len(items), items)
	}
	if items[0].ID != "CVE-2026-0002" || items[0].Scopes != 3 || len(items[0].Lines) != 3 {
		t.Errorf("first = %+v", items[0])
	}
	if items[0].Action != "Upgrade to a fixed version: 6.12.113-1." {
		t.Errorf("action = %q, want historyAction", items[0].Action)
	}
	if items[1].ID != "CVE-2026-0004" || items[1].Scopes != 2 || items[1].ScopeNames != "acme: prod; globex: prod" {
		t.Errorf("second = %+v", items[1])
	}
}

func TestP1ItemsKeepNewAndHistoryGroupsSeparate(t *testing.T) {
	it := scoped("acme", "prod", "6.12.95", "P1")
	op := report.OpenItem{ID: it.ID, Product: it.Product, Tenant: "globex", Environment: "prod", Scope: "globex/prod", Constraint: "6.12.95", Priority: "P1", FirstSeen: true}
	if got := p1Items(reportOf([]report.Item{it}, op)); len(got) != 2 {
		t.Errorf("p1Items = %d, want 2 (new and full-history are not merged)", len(got))
	}
}

func TestSummaryCardCountsFindingsAndEnvironments(t *testing.T) {
	m := buildSummaryCard(reportOf(eightScopes()), "")
	if got := textOf(m); !strings.Contains(got, "1 new finding(s) in 8 environments") {
		t.Errorf("text = %q", got)
	}
	var newFact, open string
	for _, f := range factsOf(m) {
		switch f.Title {
		case "New":
			newFact = f.Value
		case "Open":
			open = f.Value
		}
	}
	if newFact != "1 in 8 environments (P1: 1)" {
		t.Errorf("New = %q", newFact)
	}
	// Open stays per scope, so it still matches findings_open.
	if open != "8 (P1: 8)" {
		t.Errorf("Open = %q", open)
	}
	if m.Attachments[0].Content.Body[0].Color != "Attention" {
		t.Errorf("heading should stay coloured with a P1 finding")
	}
}

func TestSummaryCardCountsFindingsByHighestPriority(t *testing.T) {
	m := buildSummaryCard(reportOf([]report.Item{
		scoped("acme", "dev", "6.12.95", "P2"),
		scoped("acme", "prod", "6.12.95", "P1"),
	}), "")
	for _, f := range factsOf(m) {
		if f.Title == "New" && f.Value != "1 in 2 environments (P1: 1)" {
			t.Errorf("New = %q, want the finding counted once, as P1", f.Value)
		}
	}
}

func TestSummaryCardSingleStackUnchanged(t *testing.T) {
	a := report.Item{ID: "CVE-1", Product: "keycloak", Constraint: "26.x", Priority: "P2"}
	b := report.Item{ID: "CVE-2", Product: "argocd", Constraint: "3.x", Priority: "P3"}
	m := buildSummaryCard(reportOf([]report.Item{a, b}), "")
	if got := textOf(m); !strings.Contains(got, "2 new finding(s)") || strings.Contains(got, "environments") {
		t.Errorf("text = %q", got)
	}
	for _, f := range factsOf(m) {
		if f.Title == "New" && f.Value != "2 (P2: 1, P3: 1)" {
			t.Errorf("New = %q", f.Value)
		}
	}
	if c := m.Attachments[0].Content.Body[0].Color; c != "" {
		t.Errorf("no P1: heading colour = %q, want none", c)
	}
}
