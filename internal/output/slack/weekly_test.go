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
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
)

var weeklyNow = time.Date(2026, 11, 23, 6, 0, 0, 0, time.UTC) // a Monday

// weeklyScope is one environment of the weekly fixtures.
func weeklyScope(tenant, env, channel string) catalog.Product {
	c, _ := match.ParseConstraint("1.0.0")
	return catalog.Product{Name: "keycloak", Constraint: c, Scope: config.Scope{Tenant: tenant, Environment: env, Remote: true, Slack: config.SlackRoute{Channel: channel}}}
}

func openAt(tenant, env, product, id, prio, title string, daysAgo int) report.OpenItem {
	return report.OpenItem{ID: id, Product: product, Tenant: tenant, Environment: env, Constraint: "1.0.0", Priority: prio, Title: title,
		Link: "https://example.com/advisories/" + id, FirstReported: weeklyNow.AddDate(0, 0, -daysAgo)}
}

func closedAs(tenant, env, product, id, prio, reason string) report.ClosedItem {
	return report.ClosedItem{ID: id, Product: product, Tenant: tenant, Environment: env, Priority: prio, Reason: reason,
		Link: "https://example.com/advisories/" + id, FirstReported: weeklyNow.AddDate(0, 0, -40), ClosedAt: weeklyNow.AddDate(0, 0, -2)}
}

func weeklyRep(products []catalog.Product, open []report.OpenItem, closed []report.ClosedItem) report.Report {
	return report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: weeklyNow, Since: weeklyNow.Add(-24 * time.Hour), Until: weeklyNow,
		Products: products, Open: open, Weekly: &report.Weekly{From: weeklyNow.AddDate(0, 0, -7), Until: weeklyNow, Closed: closed}}, nil)
}

// exampleReport is the example of the weekly report: acme with its own
// channel, globex in the default one.
func exampleReport() report.Report {
	products := []catalog.Product{
		weeklyScope("acme", "dev", "C-ACME"), weeklyScope("acme", "prod", "C-ACME"), weeklyScope("acme", "stage", "C-ACME"),
		weeklyScope("globex", "test", ""),
	}
	pg := openAt("acme", "prod", "postgresql", "CVE-2025-44444", "P2", "", 142)
	pg.Action = "Upgrade to 17.6 or later."
	open := []report.OpenItem{
		openAt("acme", "dev", "debian-13-kernel", kernelID, "P1", kernelTitle, 3),
		openAt("acme", "prod", "debian-13-kernel", kernelID, "P1", kernelTitle, 3),
		openAt("acme", "prod", "keycloak", "CVE-2026-11111", "P2", "Open redirect in the login flow", 2),
		pg,
		openAt("globex", "test", "keycloak", "CVE-2026-11111", "P2", "Open redirect in the login flow", 2),
	}
	closed := []report.ClosedItem{
		closedAs("acme", "dev", "keycloak", "CVE-2026-22222", "P2", report.ClosedFixed),
		closedAs("acme", "prod", "keycloak", "CVE-2026-22222", "P2", report.ClosedFixed),
		closedAs("acme", "stage", "grafana", "CVE-2026-33333", "P3", report.ClosedRemoved),
		closedAs("globex", "old", "grafana", "CVE-2026-33333", "P3", report.ClosedRemoved), // environment left the stack
	}
	return weeklyRep(products, open, closed)
}

// rendered is the message as text: the header, then every section and
// context, separated by blank lines.
func rendered(blocks []slack.Block) string {
	var out []string
	for _, b := range blocks {
		switch x := b.(type) {
		case *slack.HeaderBlock:
			out = append(out, x.Text.Text)
		case *slack.SectionBlock:
			out = append(out, x.Text.Text)
		case *slack.ContextBlock:
			for _, e := range x.ContextElements.Elements {
				if t, ok := e.(*slack.TextBlockObject); ok {
					out = append(out, t.Text)
				}
			}
		}
	}
	return strings.Join(out, "\n\n")
}

// routeWeekly renders the weekly report of every route like Render does.
func routeWeekly(r report.Report, maxText int) map[string][]slack.Block {
	o := &Output{channel: "CDIGEST", alertChannel: "CALERT", cfg: config.SlackOutput{DashboardURL: dashboardTmpl}}
	out := map[string][]slack.Block{}
	for _, rt := range o.routes(r) {
		sub := r.ForScopes(rt.has, rt.def)
		out[rt.channel] = weeklyBlocks(sub.Weekly, rt.weeklyTitle(), o.dashboardLink(rt.tenant), maxText)
	}
	return out
}

const exampleWeekly = `:calendar: vulnwatch weekly · acme · 16 – 23 Nov 2026

*Open:* 4   :red_circle: 2   :large_orange_circle: 2
*New this week:* 2 · *Closed this week:* 2 in 3 environments

*New this week*
:red_circle: *debian-13-kernel* · *<https://example.com/advisories/CVE-2026-98432|CVE-2026-98432>*  ipv4: free inet_opt and ireq_opt after an RCU grace period
      • acme: dev, prod
:large_orange_circle: *keycloak* · *<https://example.com/advisories/CVE-2026-11111|CVE-2026-11111>*  Open redirect in the login flow
      • acme: prod

*Closed this week*
*keycloak* · *<https://example.com/advisories/CVE-2026-22222|CVE-2026-22222>* · fixed
      • acme: dev, prod
*grafana* · *<https://example.com/advisories/CVE-2026-33333|CVE-2026-33333>* · removed from the stack
      • acme: stage

*Open the longest*
:large_orange_circle: *postgresql* · *<https://example.com/advisories/CVE-2025-44444|CVE-2025-44444>* · 142 days
      ↳ Upgrade to 17.6 or later.
      • acme: prod

<https://grafana.example/d/vulnwatch/vulnwatch?from=now-30d&to=now&var-tenant=acme|:bar_chart: Open the dashboard>`

func TestWeeklyExample(t *testing.T) {
	r := exampleReport()
	msgs := routeWeekly(r, maxSectionText)
	acme := msgs["C-ACME"]
	if got := rendered(acme); got != exampleWeekly {
		t.Fatalf("got:\n%s\n\nwant:\n%s", got, exampleWeekly)
	}
	sub := r.ForScopes(func(s report.ScopeInfo) bool { return s.Tenant == "acme" }, false)
	if got := weeklyText(sub.Weekly); got != "vulnwatch weekly: 4 open, 2 new, 2 closed" {
		t.Errorf("fallback: %s", got)
	}
}

// The default channel gets globex and the closed finding of an
// environment no longer in the stack.
func TestWeeklyRoutesPerChannel(t *testing.T) {
	msgs := routeWeekly(exampleReport(), maxSectionText)
	if len(msgs) != 2 {
		t.Fatalf("routes: %v", msgs)
	}
	def := rendered(msgs["CDIGEST"])
	contains(t, def, ":calendar: vulnwatch weekly · 16 – 23 Nov 2026", "*Open:* 1   :large_orange_circle: 1",
		"*New this week:* 1 · *Closed this week:* 1", "CVE-2026-11111", "• globex: test", "CVE-2026-33333", "· removed from the stack\n      • globex: old")
	for _, not := range []string{"acme", "CVE-2026-98432", "CVE-2026-22222", "var-tenant"} {
		if strings.Contains(def, not) {
			t.Errorf("default channel shows %q:\n%s", not, def)
		}
	}
	if strings.Contains(rendered(msgs["C-ACME"]), "globex") {
		t.Error("acme's channel shows globex")
	}
}

func TestWeeklyNothing(t *testing.T) {
	r := weeklyRep([]catalog.Product{weeklyScope("acme", "prod", "")}, nil, nil)
	blocks := weeklyBlocks(r.Weekly, "", "", maxSectionText)
	if got := rendered(blocks); got != ":calendar: vulnwatch weekly · 16 – 23 Nov 2026\n\nNothing open. Nothing new or closed this week." {
		t.Fatalf("got:\n%s", got)
	}
	if got := weeklyText(r.Weekly); got != "vulnwatch weekly: 0 open, 0 new, 0 closed" {
		t.Fatalf("fallback: %s", got)
	}
}

// Open findings, but nothing new or closed: only the counts and the oldest.
func TestWeeklyQuietWeek(t *testing.T) {
	r := weeklyRep([]catalog.Product{weeklyScope("acme", "prod", "")}, []report.OpenItem{openAt("acme", "prod", "keycloak", "CVE-2025-1", "P3", "t", 60)}, nil)
	got := rendered(weeklyBlocks(r.Weekly, "", "", maxSectionText))
	contains(t, got, "*Open:* 1   :large_blue_circle: 1\n*New this week:* 0 · *Closed this week:* 0", "*Open the longest*\n:large_blue_circle: *keycloak*", "· 60 days")
	if strings.Contains(got, "*New this week*\n") || strings.Contains(got, "*Closed this week*") || strings.Contains(got, "Nothing open") {
		t.Fatalf("empty parts must be left out:\n%s", got)
	}
}

func TestWeeklyClosedReasons(t *testing.T) {
	products := []catalog.Product{weeklyScope("acme", "dev", ""), weeklyScope("acme", "prod", ""), weeklyScope("globex", "test", "")}
	titled := closedAs("acme", "dev", "keycloak", "CVE-2026-1", "P2", report.ClosedRejected)
	titled.Title = "Session fixation"
	r := weeklyRep(products, nil, []report.ClosedItem{
		titled,
		closedAs("acme", "prod", "keycloak", "CVE-2026-1", "P2", report.ClosedNotRelevant),
		closedAs("globex", "test", "keycloak", "CVE-2026-1", "P2", report.ClosedNotRelevant),
	})
	got := rendered(weeklyBlocks(r.Weekly, "", "", maxSectionText))
	// One finding; the environments closed for different reasons say so.
	contains(t, got, "*keycloak* · *<https://example.com/advisories/CVE-2026-1|CVE-2026-1>*  Session fixation\n"+
		"      • acme: dev · advisory rejected\n"+
		"      • acme: prod; globex: test · no longer relevant",
		"*Closed this week:* 1 in 3 environments")
}

func TestWeeklyLimits(t *testing.T) {
	var products []catalog.Product
	for _, tn := range []string{"acme", "globex", "initech", "umbrella"} {
		for i := range 12 {
			products = append(products, weeklyScope(tn, fmt.Sprintf("env-%02d", i), ""))
		}
	}
	long := strings.Repeat("a very long advisory title ", 60)
	var open []report.OpenItem
	var closed []report.ClosedItem
	for i := range 11 {
		id := fmt.Sprintf("CVE-2026-%d", 1000+i)
		for _, p := range products { // every finding in all 48 environments
			open = append(open, openAt(p.Scope.Tenant, p.Scope.Environment, "keycloak", id, "P2", long, 1))
			closed = append(closed, closedAs(p.Scope.Tenant, p.Scope.Environment, "grafana", id, "P3", report.ClosedFixed))
		}
	}
	r := weeklyRep(products, open, closed)
	for _, maxText := range []int{maxSectionText, 1200} {
		t.Run(fmt.Sprint(maxText), func(t *testing.T) {
			blocks := weeklyBlocks(r.Weekly, " · "+strings.Repeat("umbrella/env-00, ", 20), "", maxText)
			if len(blocks) > 50 {
				t.Fatalf("%d blocks", len(blocks))
			}
			h := blocks[0].(*slack.HeaderBlock).Text.Text
			if utf8.RuneCountInString(h) > maxHeaderText {
				t.Errorf("header %d runes", utf8.RuneCountInString(h))
			}
			secs := sections(blocks)
			for _, s := range secs {
				if n := utf8.RuneCountInString(s); n > maxText {
					t.Errorf("section of %d runes > %d", n, maxText)
				}
				if strings.Count(s, "<") != strings.Count(s, ">") {
					t.Errorf("link markup cut:\n%s", s)
				}
			}
			if len(secs) != 3 { // all open findings are new: no "Open the longest"
				t.Fatalf("%d sections", len(secs))
			}
			newSec, closedSec := secs[1], secs[2]
			if n := strings.Count(newSec, ":large_orange_circle: *keycloak*"); n == 0 || n > maxWeeklyItems {
				t.Errorf("%d new entries", n)
			}
			contains(t, newSec, "more on the dashboard_", "more environments_")
			contains(t, closedSec, "more on the dashboard_")
			// The title is cut at 200 runes.
			for _, l := range strings.Split(newSec, "\n") {
				if _, title, ok := strings.Cut(l, ">*  "); ok && utf8.RuneCountInString(title) > maxWeeklyText {
					t.Errorf("title of %d runes", utf8.RuneCountInString(title))
				}
			}
			contains(t, secs[0], "*New this week:* 11 in 48 environments · *Closed this week:* 11 in 48 environments")
		})
	}
}

func TestWeeklyElevenEntries(t *testing.T) {
	products := []catalog.Product{weeklyScope("acme", "prod", "")}
	var open []report.OpenItem
	var closed []report.ClosedItem
	for i := range 11 {
		id := fmt.Sprintf("CVE-2026-%d", 2000+i)
		open = append(open, openAt("acme", "prod", "keycloak", id, "P3", "title", 1))
		closed = append(closed, closedAs("acme", "prod", "grafana", id, "P3", report.ClosedFixed))
	}
	for i := range 11 { // and 11 reported before the week
		open = append(open, openAt("acme", "prod", "argocd", fmt.Sprintf("CVE-2025-%d", 3000+i), "P3", "title", 30+i))
	}
	secs := sections(weeklyBlocks(weeklyRep(products, open, closed).Weekly, "", "", maxSectionText))
	if len(secs) != 4 {
		t.Fatalf("%d sections", len(secs))
	}
	for _, s := range secs[1:3] {
		if n := strings.Count(s, "\n      • acme: prod"); n != maxWeeklyItems || !strings.HasSuffix(s, "\n_+1 more on the dashboard_") {
			t.Errorf("%d entries:\n%s", n, s)
		}
	}
	if n := strings.Count(secs[3], "\n      • acme: prod"); n != report.MaxOldest || strings.Contains(secs[3], "CVE-2026-") || !strings.Contains(secs[3], "CVE-2025-3010") {
		t.Errorf("oldest: %d entries:\n%s", n, secs[3])
	}
}

func TestWeeklyEscaping(t *testing.T) {
	// Tenant and environment names cannot hold these characters in
	// stack.yaml; they are escaped all the same.
	const tenant, env = "a<c&m>e", "p<r&o>d"
	products := []catalog.Product{weeklyScope(tenant, env, "")}
	it := openAt(tenant, env, "key<cloak>&co", "CVE-2026-1", "P2", "<!channel> & <https://evil.example|click>", 1)
	old := openAt(tenant, env, "x&y", "CVE-2025-1", "P3", "old <i>", 30) // under Open the longest, with its action
	old.Action = "Run `x` > y & z"
	cl := closedAs(tenant, env, "a&b", "CVE-2026-2", "P2", report.ClosedFixed)
	cl.Title = "fix <b>"
	got := rendered(weeklyBlocks(weeklyRep(products, []report.OpenItem{it, old}, []report.ClosedItem{cl}).Weekly, "", "", maxSectionText))
	contains(t, got, "*key&lt;cloak&gt;&amp;co*", "&lt;!channel&gt; &amp; &lt;https://evil.example|click&gt;", "Run `x` &gt; y &amp; z",
		"*a&amp;b*", "fix &lt;b&gt;", "*x&amp;y*", "old &lt;i&gt;", "• a&lt;c&amp;m&gt;e: p&lt;r&amp;o&gt;d")
	if n := strings.Count(got, "      • a&lt;c&amp;m&gt;e: p&lt;r&amp;o&gt;d"); n != 3 {
		t.Errorf("%d escaped environment lines, want one per entry", n)
	}
	for _, bad := range []string{"&amp;lt;", "&amp;amp;", "&amp;gt;", "<!channel>", "<https://evil", "a<c", "p<r"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q in:\n%s", bad, got)
		}
	}
}

// A route of one tenant is named by the tenant, a route of several by its
// environments, like the summary; the default route has no name.
func TestWeeklyTitle(t *testing.T) {
	products := []catalog.Product{
		weeklyScope("acme", "prod", "C-ACME"), weeklyScope("globex", "test", "C-SHARED"), weeklyScope("initech", "prod", "C-SHARED"),
		weeklyScope("umbrella", "prod", ""),
	}
	msgs := routeWeekly(weeklyRep(products, nil, nil), maxSectionText)
	for ch, want := range map[string]string{
		"C-ACME":   ":calendar: vulnwatch weekly · acme · 16 – 23 Nov 2026",
		"C-SHARED": ":calendar: vulnwatch weekly · globex/test, initech/prod · 16 – 23 Nov 2026",
		"CDIGEST":  ":calendar: vulnwatch weekly · 16 – 23 Nov 2026",
	} {
		if got := msgs[ch][0].(*slack.HeaderBlock).Text.Text; got != want {
			t.Errorf("%s: %q, want %q", ch, got, want)
		}
	}
}

// Render posts the weekly report after the summary to each route's channel,
// with an audit entry, and keeps going when one route fails.
func TestRenderPostsWeekly(t *testing.T) {
	srv, msgs := fakeSlack(t, false, "C-ACME")
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")
	var logs bytes.Buffer
	o.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: logx.LevelAudit}))
	err := o.Render(context.Background(), exampleReport())
	if err == nil || !strings.Contains(err.Error(), "slack weekly C-ACME") {
		t.Fatalf("want the failed weekly post, got %v", err)
	}
	var got []string
	for _, m := range *msgs {
		got = append(got, m.Channel+" "+m.Text)
	}
	want := []string{
		"CDIGEST vulnwatch: no new vulnerabilities, 1 open",
		"CDIGEST vulnwatch weekly: 1 open, 1 new, 1 closed",
		"C-ACME vulnwatch: no new vulnerabilities, 4 open",
		"C-ACME vulnwatch weekly: 4 open, 2 new, 2 closed",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("posts:\n%s", strings.Join(got, "\n"))
	}
	if strings.Count(logs.String(), "kind=weekly") != 1 || !strings.Contains(logs.String(), "channel=CDIGEST") {
		t.Fatalf("audit:\n%s", logs.String())
	}
}
