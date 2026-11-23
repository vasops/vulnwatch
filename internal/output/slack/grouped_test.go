package slack

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

const (
	kernelID    = "CVE-2026-98432"
	kernelTitle = "ipv4: free inet_opt and ireq_opt after an RCU grace period"
	kernelFix   = "Upgrade the debian-13 kernel on all Kubernetes nodes to 6.12.113-1 or later, then drain and reboot the nodes one at a time."
)

// scope is one tenant environment running the product in a version.
type scope struct {
	tenant, env, version, prio, action, change string
	slackChannel                               string
}

func kernelScopes() []scope {
	return []scope{
		{tenant: "acme", env: "dev", version: "6.12.95"},
		{tenant: "globex", env: "test", version: "6.12.95"},
		{tenant: "acme", env: "prod", version: "6.12.95 || 6.12.101"},
		{tenant: "initech", env: "dev", version: "6.12.57"},
		{tenant: "initech", env: "stage", version: "6.12.57"},
		{tenant: "initech", env: "prod", version: "6.12.62"},
		{tenant: "umbrella", env: "prod", version: "6.12.88 || 6.12.115 || 6.12.116"},
	}
}

// buildReport builds a multi-tenant report with the finding id in every
// scope; empty prio, action and change default to P1, kernelFix and new.
func buildReport(t *testing.T, id, title string, scopes []scope) report.Report {
	t.Helper()
	var ps []catalog.Product
	var es []report.Entry
	for _, s := range scopes {
		c, err := match.ParseConstraint(s.version)
		if err != nil {
			t.Fatal(err)
		}
		p := catalog.Product{Name: "debian-13-kernel", Constraint: c, Exposure: "internal", Criticality: "high",
			Scope: config.Scope{Tenant: s.tenant, Environment: s.env, Remote: true, Slack: config.SlackRoute{Channel: s.slackChannel}}}
		ps = append(ps, p)
		es = append(es, report.Entry{
			Finding: finding.Finding{ID: id, Product: p.Key(), Title: title, Severity: "high", Match: "affected", Fixed: []string{"6.12.113"}},
			Product: p,
			Triage:  triage.Result{Relevant: "yes", Priority: cmpOr(s.prio, "P1"), Method: triage.MethodRules, Action: cmpOr(s.action, kernelFix), Summary: "Claude's explanation"},
			Change:  s.change,
		})
	}
	now := time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC)
	return report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now, Products: ps}, es)
}

// sections is the text of every section block, and fields the text of
// every field of the section blocks.
func sections(blocks []slack.Block) []string {
	var out []string
	for _, b := range blocks {
		if s, ok := b.(*slack.SectionBlock); ok {
			out = append(out, s.Text.Text)
		}
	}
	return out
}

func fields(blocks []slack.Block) string {
	var out []string
	for _, b := range blocks {
		if s, ok := b.(*slack.SectionBlock); ok {
			for _, f := range s.Fields {
				out = append(out, f.Text)
			}
		}
	}
	return strings.Join(out, "\n")
}

func summaryOf(r report.Report, maxText int) []slack.Block {
	return summaryBlocks(r, "", "", p1Total(p1Alerts(r)), "CALERT", nil, maxText)
}

func contains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func TestGroupedSummaryOneEntryForEightScopes(t *testing.T) {
	scopes := append(kernelScopes(), scope{tenant: "umbrella", env: "stage", version: "6.12.88 || 6.12.115 || 6.12.116"})
	rep := buildReport(t, kernelID, kernelTitle, scopes)
	blocks := summaryOf(rep, maxSectionText)
	secs := sections(blocks)
	// head, one finding, tail
	if len(secs) != 3 {
		t.Fatalf("%d sections:\n%s", len(secs), strings.Join(secs, "\n--\n"))
	}
	contains(t, secs[0], ":rotating_light: *1 critical (P1) finding in 8 environments*, see <#CALERT>", "*New:* 1 in 8 environments   :red_circle: 1")
	entry := secs[1]
	t.Logf("rendered entry:\n%s", strings.Join(secs, "\n\n"))
	want := ":red_circle: *debian-13-kernel* · *" + kernelID + "*\n" + kernelTitle + "\n" +
		"      ↳ " + kernelFix + "\n" +
		"      • acme: dev; globex: test · `6.12.95`\n" +
		"      • acme: prod · `6.12.95, 6.12.101`\n" +
		"      • initech: dev, stage · `6.12.57`\n" +
		"      • initech: prod · `6.12.62`\n" +
		"      • umbrella: prod, stage · `6.12.88, 6.12.115, 6.12.116`"
	if entry != want {
		t.Errorf("entry:\n%s\nwant:\n%s", entry, want)
	}
	if got := summaryText(rep); got != "vulnwatch: 1 new or updated vulnerability in 8 environments, 8 open" {
		t.Errorf("text %q", got)
	}
	contains(t, secs[2], "*Open:* 8 (new 8)")
}

func TestGroupedP1CardHasAffectedList(t *testing.T) {
	scopes := append(kernelScopes(), scope{tenant: "umbrella", env: "stage", version: "6.12.88 || 6.12.115 || 6.12.116"})
	alerts := p1Alerts(buildReport(t, kernelID, kernelTitle, scopes))
	if len(alerts) != 1 {
		t.Fatalf("%d cards", len(alerts))
	}
	a := alerts[0]
	if a.text != "P1: debian-13-kernel "+kernelID+" (8 environments)" || a.count != 1 || len(a.scopes) != 8 {
		t.Errorf("alert %q count %d scopes %d", a.text, a.count, len(a.scopes))
	}
	b := a.blocks("", maxSectionText)
	if h := b[0].(*slack.HeaderBlock).Text.Text; h != ":rotating_light: P1 · debian-13-kernel · "+kernelID+" · 8 environments" {
		t.Errorf("header %q", h)
	}
	contains(t, fields(b), "*Affected*\n• acme: dev; globex: test · `6.12.95`\n• acme: prod · `6.12.95, 6.12.101`", "*Fixed in*\n6.12.113")
	if strings.Contains(fields(b), "Our version") {
		t.Errorf("Our version stays only without tenants:\n%s", fields(b))
	}
	contains(t, sections(b)[0], "Claude's explanation", "*"+kernelFix+"*")
	if strings.Contains(sections(b)[0], "`6.12") {
		t.Errorf("no version in the text of a scoped card:\n%s", sections(b)[0])
	}
	contains(t, blockContext(b), "new")
}

func blockContext(blocks []slack.Block) string {
	var out []string
	for _, b := range blocks {
		if c, ok := b.(*slack.ContextBlock); ok {
			for _, e := range c.ContextElements.Elements {
				if tx, ok := e.(*slack.TextBlockObject); ok {
					out = append(out, tx.Text)
				}
			}
		}
	}
	return strings.Join(out, "\n")
}

func TestGroupedMixedPriorities(t *testing.T) {
	rep := buildReport(t, kernelID, kernelTitle, []scope{
		{tenant: "acme", env: "dev", version: "6.12.95", prio: "P2"},
		{tenant: "acme", env: "prod", version: "6.12.95"},
	})
	secs := sections(summaryOf(rep, maxSectionText))
	// P1 scopes come first in the report; the P2 line carries its own emoji.
	contains(t, secs[1], ":red_circle: *debian-13-kernel* ·", "      • acme: prod · `6.12.95`\n      • :large_orange_circle: acme: dev · `6.12.95`")
	contains(t, secs[0], "*1 critical (P1) finding*, see", "*New:* 1 in 2 environments   :red_circle: 1")
	if strings.Contains(strings.SplitN(secs[0], "\n", 2)[0], "environments") {
		t.Errorf("the P1 line counts the P1 scopes only:\n%s", secs[0])
	}
	// The card lists only the P1 scope, in the one-scope form.
	a := p1Alerts(rep)
	if len(a) != 1 || len(a[0].scopes) != 1 {
		t.Fatalf("%+v", a)
	}
	b := a[0].blocks("", maxSectionText)
	// One scope on one line: the card keeps its one-scope form.
	if h := b[0].(*slack.HeaderBlock).Text.Text; h != ":rotating_light: P1 · acme/prod debian-13-kernel · "+kernelID {
		t.Errorf("header %q", h)
	}
	if a[0].text != "P1: acme/prod debian-13-kernel "+kernelID {
		t.Errorf("text %q", a[0].text)
	}
	contains(t, sections(b)[0], "*acme/prod debian-13-kernel*") // product name in the text line
	contains(t, sections(b)[0], "`6.12.95`")
	contains(t, fields(b), "*Our version*\naffected")
	if strings.Contains(fields(b), "Affected") || strings.Contains(fields(b), "dev") {
		t.Errorf("one-scope card has an Affected list or the dev scope:\n%s", fields(b))
	}
}

func TestGroupedDifferentActionsShowTheCommonOne(t *testing.T) {
	rep := buildReport(t, kernelID, kernelTitle, []scope{
		{tenant: "acme", env: "dev", version: "6.12.95", action: "Upgrade acme first."},
		{tenant: "globex", env: "test", version: "6.12.95"},
		{tenant: "initech", env: "dev", version: "6.12.57"},
	})
	entry := sections(summaryOf(rep, maxSectionText))[1]
	if strings.Count(entry, "↳") != 1 || !strings.Contains(entry, kernelFix) || strings.Contains(entry, "acme first") {
		t.Errorf("entry:\n%s", entry)
	}
}

func TestGroupedDifferentChangesShowOnScopeLines(t *testing.T) {
	rep := buildReport(t, kernelID, kernelTitle, []scope{
		{tenant: "acme", env: "dev", version: "6.12.95"},
		{tenant: "globex", env: "test", version: "6.12.57", change: "fixed version released: 6.12.113"},
	})
	entry := sections(summaryOf(rep, maxSectionText))[1]
	contains(t, entry, "      • acme: dev · `6.12.95`\n", "      • globex: test · `6.12.57` _(updated: fixed version released: 6.12.113)_")
	if strings.Contains(strings.SplitN(entry, "\n", 2)[0], "updated") {
		t.Errorf("no shared change after the ID:\n%s", entry)
	}
	// All scopes share a change: it follows the ID.
	rep = buildReport(t, kernelID, kernelTitle, []scope{
		{tenant: "acme", env: "dev", version: "6.12.95", change: "KEV added"},
		{tenant: "globex", env: "test", version: "6.12.57", change: "KEV added"},
	})
	entry = sections(summaryOf(rep, maxSectionText))[1]
	contains(t, entry, "*"+kernelID+"* _(updated: KEV added)_\n")
	if strings.Contains(entry, "• acme: dev · `6.12.95` _") {
		t.Errorf("shared change repeated on the lines:\n%s", entry)
	}
	blocks := p1Alerts(rep)[0].blocks("", maxSectionText)
	contains(t, blockContext(blocks), "updated: KEV added")
}

func TestGroupedSingleScopeAndSingleStackKeepOneLine(t *testing.T) {
	long := strings.TrimSpace(strings.Repeat("a long advisory title ", 10)) // a long title is shown in full
	rep := buildReport(t, kernelID, long, []scope{{tenant: "acme", env: "prod", version: "6.12.95"}})
	entry := sections(summaryOf(rep, maxSectionText))[1]
	want := ":red_circle: *acme/prod debian-13-kernel* `6.12.95` · *" + kernelID + "* " + long + "\n      ↳ " + kernelFix
	if entry != want {
		t.Errorf("entry:\n%s\nwant:\n%s", entry, want)
	}
	a := p1Alerts(rep)
	if len(a) != 1 || a[0].text != "P1: acme/prod debian-13-kernel "+kernelID {
		t.Fatalf("%+v", a)
	}

	// No tenants: one line, no scope lines.
	it := report.Item{ID: kernelID, Product: "keycloak", Constraint: "26.x", Title: long, Priority: "P1", Change: "new", Action: "Upgrade."}
	f := report.Findings([]report.Item{it})[0]
	entry = summaryEntry(f, maxSectionText)
	if entry != ":red_circle: *keycloak* `26.x` · *"+kernelID+"* "+long+"\n      ↳ Upgrade." {
		t.Errorf("entry:\n%s", entry)
	}
}

func TestGroupedManyScopesFitMaxText(t *testing.T) {
	var scopes []scope
	for i := range 200 {
		scopes = append(scopes, scope{tenant: fmt.Sprintf("tenant%02d", i), env: "prod", version: fmt.Sprintf("6.12.%d", i)})
	}
	rep := buildReport(t, kernelID, kernelTitle, scopes)
	for _, maxText := range []int{maxSectionText, 800} {
		entry := sections(summaryOf(rep, maxText))[1]
		if n := utf8.RuneCountInString(entry); n > maxText {
			t.Errorf("max %d: entry is %d runes", maxText, n)
		}
		if !strings.Contains(entry, " more environments_") {
			t.Errorf("max %d: no +N more environments:\n%s", maxText, entry)
		}
	}
	card := p1Alerts(rep)[0].blocks("", maxSectionText)
	if !strings.Contains(fields(card), " more environments_") {
		t.Errorf("card fields:\n%s", fields(card))
	}
	for _, f := range card[1].(*slack.SectionBlock).Fields {
		if utf8.RuneCountInString(f.Text) > 2000 {
			t.Errorf("field over Slack's 2000: %d", utf8.RuneCountInString(f.Text))
		}
	}
}

func TestGroupedLongTitleAndActionKeepMoreEnvironments(t *testing.T) {
	var scopes []scope
	for i := range 50 {
		scopes = append(scopes, scope{tenant: fmt.Sprintf("tenant%02d", i), env: "prod", version: fmt.Sprintf("6.12.%d", i), action: strings.Repeat("b", 600)})
	}
	rep := buildReport(t, kernelID, strings.Repeat("a", 600), scopes)
	entry := sections(summaryOf(rep, 500))[1]
	if n := utf8.RuneCountInString(entry); n > 500 {
		t.Errorf("entry is %d runes", n)
	}
	for _, want := range []string{"↳", "more environments"} {
		if !strings.Contains(entry, want) {
			t.Errorf("entry missing %q:\n%s", want, entry)
		}
	}
}

func TestGroupedElevenFindings(t *testing.T) {
	var all report.Report
	for i := range 11 {
		r := buildReport(t, fmt.Sprintf("CVE-2026-%04d", i), "t", []scope{{tenant: "acme", env: "dev", version: "6.12.95", prio: "P2"}, {tenant: "globex", env: "dev", version: "6.12.95", prio: "P2"}})
		if i == 0 {
			all = r
			continue
		}
		all.Groups[0].Products[0].Items = append(all.Groups[0].Products[0].Items, r.Items()...)
	}
	blocks := summaryOf(all, maxSectionText)
	secs := sections(blocks)
	if len(blocks) > 50 {
		t.Fatalf("%d blocks", len(blocks))
	}
	entries := 0
	for _, s := range secs {
		if strings.HasPrefix(s, ":large_orange_circle:") {
			entries++
		}
	}
	if entries != maxSummaryItems {
		t.Errorf("%d entries listed:\n%s", entries, strings.Join(secs, "\n--\n"))
	}
	contains(t, strings.Join(secs, "\n"), "_+1 more on the dashboard_")
}

func TestGroupedHistoryCards(t *testing.T) {
	rep := buildReport(t, kernelID, kernelTitle, nil)
	rep.MultiTenant = true
	for _, s := range []scope{{tenant: "acme", env: "prod", version: "6.12.95"}, {tenant: "globex", env: "prod", version: "6.12.57"}} {
		rep.Open = append(rep.Open, report.OpenItem{ID: "CVE-2024-0001", Product: "debian-13-kernel", Tenant: s.tenant, Environment: s.env, Scope: s.tenant + "/" + s.env,
			Constraint: s.version, Title: "old", Severity: "high", Match: "affected", Priority: "P1", Fixed: []string{"6.12.113"}, FirstSeen: true})
	}
	a := p1Alerts(rep)
	if len(a) != 1 || a[0].count != 1 || len(a[0].scopes) != 2 || a[0].text != "P1: debian-13-kernel CVE-2024-0001 (2 environments)" {
		t.Fatalf("%+v", a)
	}
	contains(t, fields(a[0].blocks("", maxSectionText)), "• acme: prod · `6.12.95`", "• globex: prod · `6.12.57`")

	// Above maxHistoryCards findings one card lists them, with the lines under each.
	for i := range maxHistoryCards + 1 {
		rep.Open = append(rep.Open, report.OpenItem{ID: fmt.Sprintf("CVE-2023-%04d", i), Product: "debian-13-kernel", Tenant: "acme", Environment: "prod", Scope: "acme/prod",
			Constraint: "6.12.95", Priority: "P1", FirstSeen: true})
		rep.Open = append(rep.Open, report.OpenItem{ID: fmt.Sprintf("CVE-2023-%04d", i), Product: "debian-13-kernel", Tenant: "globex", Environment: "prod", Scope: "globex/prod",
			Constraint: "6.12.57", Priority: "P1", FirstSeen: true})
	}
	a = p1Alerts(rep)
	if len(a) != 1 || a[0].count != maxHistoryCards+2 || len(a[0].scopes) != 2 {
		t.Fatalf("one card for %d findings, got %d cards: %+v", maxHistoryCards+2, len(a), a)
	}
	text := sections(a[0].blocks("", maxSectionText))[0]
	contains(t, text, ":red_circle: *CVE-2024-0001* · *debian-13-kernel*\n", "      • acme: prod · `6.12.95`\n      • globex: prod · `6.12.57`")
	if p := p1Total(a); p.findings != maxHistoryCards+2 || p.scopes != 2 {
		t.Errorf("%+v", p)
	}
}

func TestGroupedInjectionInTenantNamesAndText(t *testing.T) {
	rep := buildReport(t, kernelID, "<!channel> & <@U1>", []scope{
		{tenant: "<!here>", env: "a&b", version: "6.12.95", action: "<https://evil.example|click>"},
		{tenant: "acme", env: "<prod>", version: "6.12.57", action: "<https://evil.example|click>"},
	})
	var all []string
	all = append(all, sections(summaryOf(rep, maxSectionText))...)
	for _, a := range p1Alerts(rep) {
		b := a.blocks("", maxSectionText)
		all = append(all, a.text, fields(b), sections(b)[0])
	}
	got := strings.Join(all, "\n")
	for _, bad := range []string{"<!", "<@", "<https://evil", "<prod>"} {
		if strings.Contains(got, bad) {
			t.Errorf("markup %q injected:\n%s", bad, got)
		}
	}
	contains(t, got, "&lt;!here&gt;: a&amp;b", "acme: &lt;prod&gt;")
}

// Render itself: these tests start a server.

func TestGroupedRenderRoutesPerChannelAndAudits(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")
	var logs bytes.Buffer
	o.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: logx.LevelAudit}))

	rep := buildReport(t, kernelID, kernelTitle, []scope{
		{tenant: "acme", env: "dev", version: "6.12.95", slackChannel: "C-ACME"},
		{tenant: "acme", env: "prod", version: "6.12.57", slackChannel: "C-ACME"},
		{tenant: "globex", env: "test", version: "6.12.95"},
		{tenant: "initech", env: "dev", version: "6.12.62"},
	})
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range *msgs {
		got = append(got, m.Channel)
	}
	// Default route: summary and one card; acme: its own summary and one card.
	if strings.Join(got, " ") != "CDIGEST CALERT C-ACME C-ACME" {
		t.Fatalf("channels %v", got)
	}
	def, acme := blockText((*msgs)[0].Blocks), blockText((*msgs)[2].Blocks)
	contains(t, def, "globex: test · `6.12.95`", "initech: dev · `6.12.62`", "*1 critical (P1) finding in 2 environments*")
	if strings.Contains(def, "acme") {
		t.Errorf("default summary lists acme:\n%s", def)
	}
	contains(t, acme, "acme: dev · `6.12.95`", "acme: prod · `6.12.57`", "*1 critical (P1) finding in 2 environments*")
	if strings.Contains(acme, "globex") {
		t.Errorf("acme summary lists globex:\n%s", acme)
	}
	if n := strings.Count(logs.String(), "kind=p1_alert"); n != 2 {
		t.Errorf("%d p1_alert audit entries, want one per card:\n%s", n, logs.String())
	}
	contains(t, logs.String(), `scopes="acme: dev, prod"`, `scopes="globex: test; initech: dev"`)
}
