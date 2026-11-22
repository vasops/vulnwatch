// Package slack posts through a Slack App bot token (chat.postMessage,
// Block Kit): one short summary per run, with a link to the Grafana
// dashboard for the details, plus one critical alert per P1 finding learned
// in this run (many from a full-history check share one). Full lists live in
// the dashboard and the HTML/JSON reports.
package slack

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/textx"
)

// Header text is plain_text and capped at 150 characters by Slack.
const maxHeaderText = 150

type Output struct {
	cfg          config.SlackOutput
	api          *slack.Client
	channel      string
	alertChannel string
	newsChannel  string
	log          *slog.Logger
	sleep        func(context.Context, time.Duration) error
}

// Settings are resolved from env vars by the caller.
type Settings struct {
	Token        string
	Channel      string
	AlertChannel string // falls back to Channel
	NewsChannel  string // vulnwatch news; falls back to Channel
}

func New(cfg config.SlackOutput, s Settings, hc *http.Client, log *slog.Logger) (*Output, error) {
	if s.Token == "" || s.Channel == "" {
		return nil, fmt.Errorf("slack output needs %s and %s", cfg.TokenEnv, cfg.ChannelEnv)
	}
	opts := []slack.Option{slack.OptionAPIURL(cfg.BaseURL)}
	if hc != nil {
		opts = append(opts, slack.OptionHTTPClient(hc))
	}
	alert := s.AlertChannel
	if alert == "" {
		alert = s.Channel
	}
	return &Output{
		cfg: cfg, api: slack.New(s.Token, opts...), channel: s.Channel, alertChannel: alert, newsChannel: cmpOr(s.NewsChannel, s.Channel), log: log,
		sleep: sleepCtx,
	}, nil
}

func (o *Output) Name() string { return "slack" }

// Render posts to every route even when one fails (a missing channel must
// not starve the others), and every P1 card even when its summary failed.
// The joined error fails the run, so the state is not written and the next
// run posts everything again: delivery is at-least-once.
func (o *Output) Render(ctx context.Context, r report.Report) error {
	var errs []error
	failed := r.FailedSources() // run-wide: every route says the run was incomplete
	for _, rt := range o.routes(r) {
		if ctx.Err() != nil {
			break
		}
		sub := r
		if r.MultiTenant {
			sub = r.ForScopes(rt.has, rt.def)
		}
		dash := o.dashboardLink(rt.tenant)
		alerts := p1Alerts(sub)
		p1 := 0
		for _, a := range alerts {
			p1 += a.count
		}
		if err := o.post(ctx, rt.channel, summaryText(sub), summaryBlocks(sub, rt.title, dash, p1, rt.alert, failed, o.maxText())); err != nil {
			errs = append(errs, fmt.Errorf("slack summary %s: %w", rt.channel, err))
		} else {
			logx.Audit(ctx, o.log, "slack message posted", "kind", "summary", "channel", rt.channel, "scopes", strings.TrimPrefix(rt.title, " · "),
				"new", sub.Total(), "still_open", len(sub.Open))
		}
		for _, a := range alerts {
			if err := o.post(ctx, rt.alert, a.text, a.blocks(dash, o.maxText())); err != nil {
				errs = append(errs, fmt.Errorf("slack P1 alert %s %s: %w", rt.alert, a.id, err))
				if ctx.Err() != nil {
					break
				}
				continue
			}
			logx.Audit(ctx, o.log, "slack message posted", "kind", "p1_alert", "channel", rt.alert, "id", a.id, "text", a.text)
		}
	}
	if err := ctx.Err(); err != nil && !slices.ContainsFunc(errs, func(e error) bool { return errors.Is(e, err) }) {
		errs = append(errs, err) // cancelled between posts
	}
	return errors.Join(errs...)
}

// maxSectionText is Slack's limit for a section block's text; longer text
// is rejected (invalid_blocks), and a rejected post repeats every run.
const maxSectionText = 3000

// maxText is outputs.slack.max_section_text, at most Slack's limit.
func (o *Output) maxText() int {
	if n := o.cfg.MaxSectionText; n > 0 && n < maxSectionText {
		return n
	}
	return maxSectionText
}

// route is where the messages of some scopes go.
type route struct {
	channel, alert string
	scopes         []report.ScopeInfo
	def            bool   // the default channels: also run-wide facts (warnings)
	title          string // " · acme/prod" for a tenant's own channels
	tenant         string // the one tenant routed here, for the dashboard link
}

func (rt route) has(s report.ScopeInfo) bool {
	return slices.ContainsFunc(rt.scopes, func(x report.ScopeInfo) bool { return x.Tenant == s.Tenant && x.Environment == s.Environment })
}

// routes groups the scopes by their channels. A tenant (or environment)
// with its own channel gets its own summary and alerts there (its alert
// channel, else the same channel); the rest, and the local stack, go to
// the default channels, which always get a summary.
func (o *Output) routes(r report.Report) []route {
	out := []route{{channel: o.channel, alert: o.alertChannel, def: true}}
	if !r.MultiTenant {
		return out
	}
	idx := map[[2]string]int{{o.channel, o.alertChannel}: 0}
	for _, s := range r.Scopes {
		ch, al := o.channel, cmp.Or(s.Slack.AlertChannel, o.alertChannel)
		if s.Slack.Channel != "" {
			ch, al = s.Slack.Channel, cmp.Or(s.Slack.AlertChannel, s.Slack.Channel)
		}
		k := [2]string{ch, al}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, route{channel: ch, alert: al})
		}
		out[i].scopes = append(out[i].scopes, s)
	}
	for i := range out[1:] {
		rt := &out[i+1]
		var names []string
		tenants := map[string]bool{}
		for _, s := range rt.scopes {
			names = append(names, s.String())
			tenants[s.Tenant] = true
		}
		rt.title = " · " + strings.Join(names, ", ")
		if len(tenants) == 1 {
			rt.tenant = rt.scopes[0].Tenant
		}
	}
	return out
}

// post sends one message, spacing posts and honoring rate-limit responses.
func (o *Output) post(ctx context.Context, channel, text string, blocks []slack.Block) error {
	opts := []slack.MsgOption{
		slack.MsgOptionText(text, true), // escapes & < >: no markup or mentions from advisory text
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionDisableLinkUnfurl(),
	}
	for attempt := 0; ; attempt++ {
		_, _, err := o.api.PostMessageContext(ctx, channel, opts...)
		var rl *slack.RateLimitedError
		if errors.As(err, &rl) && attempt < 3 {
			o.log.Warn("slack rate limited", "retry_after", rl.RetryAfter)
			if err := o.sleep(ctx, rl.RetryAfter); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		return o.sleep(ctx, o.cfg.PostInterval.D())
	}
}

// dashboardLink fills the configured Grafana URL: {from} and {to} become
// now-30d and now, the 30 days up to the click. A window fixed to the run
// would end in the future when clicked right away, and before the metrics
// the run pushes at its end are scraped, so the panels would show the
// previous run.
// For a tenant's own channel the link selects the tenant (var-tenant).
func (o *Output) dashboardLink(tenant string) string {
	if o.cfg.DashboardURL == "" {
		return ""
	}
	link := strings.NewReplacer("{from}", "now-30d", "{to}", "now").Replace(o.cfg.DashboardURL)
	if tenant != "" {
		sep := "?"
		if strings.Contains(link, "?") {
			sep = "&"
		}
		link += sep + "var-tenant=" + url.QueryEscape(tenant)
	}
	return link
}

// prioEmoji marks priorities consistently in every message.
var prioEmoji = map[string]string{"P1": ":red_circle:", "P2": ":large_orange_circle:", "P3": ":large_blue_circle:", "P4": ":white_circle:"}

// summaryText is the notification / fallback text.
func summaryText(r report.Report) string {
	text := "vulnwatch: no new vulnerabilities"
	if !r.Empty() {
		text = fmt.Sprintf("vulnwatch: %d new or updated %s", r.Total(), plural(r.Total(), "vulnerability", "vulnerabilities"))
	}
	if n := sum(r.CurrentOpenCounts()); n > 0 {
		text += fmt.Sprintf(", %d open", n)
	}
	return text
}

func sum(cs []report.PriorityCount) int {
	n := 0
	for _, c := range cs {
		n += c.Count
	}
	return n
}

// summaryBlocks is the per-run message: status, counts and where to look.
// failed names the sources that failed in the run (for every route; the
// warning count only where the run's warnings are kept).
// The section stays within maxText: findings that don't fit are dropped
// whole and counted in the "+N more" line.
func summaryBlocks(r report.Report, scopes, dash string, alerts int, alertChannel string, failed []string, maxText int) []slack.Block {
	title := ":shield: vulnwatch report" + scopes + " · " + r.Until.Format("2 Jan 2006")
	if r.Mode != report.ModeRun {
		title += " (" + r.Mode + ")"
	}
	var head, tail []string
	if alerts > 0 {
		head = append(head, fmt.Sprintf(":rotating_light: *%d critical (P1) %s*, see <#%s>", alerts, plural(alerts, "finding", "findings"), alertChannel))
	}
	if n := r.TriageFailures; n > 0 { // run-wide: on every route
		head = append(head, fmt.Sprintf(":warning: Claude triage failed %d %s; priorities are rule-based", n, plural(n, "time", "times")))
	}
	newLine := "*New:* none"
	if !r.Empty() {
		newLine = fmt.Sprintf("*New:* %d   %s", r.Total(), countLine(r.Counts))
	}
	head = append(head, newLine)
	// Open counts like the findings_open metric: listed now plus still open.
	open := r.CurrentOpenCounts()
	tail = append(tail, fmt.Sprintf("*Open:* %d (new %d)   %s", sum(open), r.Total(), countLine(open)))
	if n := len(r.Baselines); n > 0 {
		tail = append(tail, fmt.Sprintf("*Full history checked:* %d %s (%s)", n, plural(n, "product", "products"), baselineReasons(r.Baselines)))
	}
	if dash != "" {
		tail = append(tail, "<"+dash+"|:bar_chart: Open the dashboard>")
	}
	ctx := []string{
		fmt.Sprintf("%d products", len(r.Products)),
		r.Since.Format("2 Jan 15:04") + " → " + r.Until.Format("2 Jan 15:04 MST"),
	}
	if len(failed) > 0 {
		note := fmt.Sprintf(":warning: incomplete: %s %s failed", plural(len(failed), "source", "sources"), escape(strings.Join(failed, ", ")))
		if n := len(r.Warnings); n > 0 {
			note += fmt.Sprintf(" (%d %s, see the job log)", n, plural(n, "warning", "warnings"))
		}
		ctx = append(ctx, note)
	}
	return []slack.Block{
		slack.NewHeaderBlock(plain(textx.Truncate(title, maxHeaderText))),
		slack.NewSectionBlock(mrkdwn(fitSummary(head, groupItems(r.Items()), tail, maxText)), nil, nil),
		slack.NewContextBlock("", mrkdwn(strings.Join(ctx, "  ·  "))),
	}
}

// maxSummaryItems is how many new findings the summary lists.
const maxSummaryItems = 10

// fitSummary joins the head lines, the new and updated findings (most
// urgent first: priority, product and version, the advisory, then the
// action) and the tail lines. It lists as many findings as fit in maxText
// runes, at most maxSummaryItems, dropping whole findings (never cutting
// inside link markup); the rest are counted in a "+N more" line.
func fitSummary(head []string, groups []*itemGroup, tail []string, maxText int) string {
	var text string
	for k := min(len(groups), maxSummaryItems); k >= 0; k-- {
		lines := slices.Clone(head)
		for _, g := range groups[:k] {
			lines = append(lines, g.lines()...)
		}
		if k < len(groups) {
			lines = append(lines, fmt.Sprintf("      _+%d more on the dashboard_", len(groups)-k))
		}
		text = strings.Join(append(lines, tail...), "\n")
		if utf8.RuneCountInString(text) <= maxText {
			return text
		}
	}
	return truncate(text, maxText) // head and tail alone are too long
}

// itemGroup is one finding as listed in the summary, with every scope
// (tenant environment) it was reported for.
type itemGroup struct {
	report.Item
	scopes [][2]string // tenant, environment
}

// groupItems merges items that differ only in their scope, keeping the
// report order (by first appearance).
func groupItems(items []report.Item) []*itemGroup {
	type key struct{ product, constraint, id, priority, change, action string }
	idx := map[key]*itemGroup{}
	var out []*itemGroup
	for _, it := range items {
		k := key{it.Product, it.Constraint, it.ID, it.Priority, it.Change, it.Action}
		g := idx[k]
		if g == nil {
			g = &itemGroup{Item: it}
			idx[k] = g
			out = append(out, g)
		}
		if it.Scope != "" {
			g.scopes = append(g.scopes, [2]string{it.Tenant, it.Environment})
		}
	}
	return out
}

// lines renders the group: the finding, then its action.
func (g *itemGroup) lines() []string {
	it := g.Item
	link := ""
	for _, a := range it.Advisories {
		link = a.URL
		break
	}
	link = cmpOr(link, first(it.Links))
	name := "*" + escape(it.Product) + "*"
	switch {
	case len(g.scopes) == 1:
		name = "*" + escape(report.Named(it.Scope, it.Product)) + "*"
	case len(g.scopes) > 1:
		name += " (" + escape(scopeList(g.scopes)) + ")"
	}
	line := fmt.Sprintf("%s %s `%s` · %s", prioEmoji[it.Priority], name, escape(versions(it.Constraint)), idLink(it.ID, it.Title, link))
	if it.Title != "" && report.Label(it.ID, it.Title) == it.ID {
		line += " " + escape(textx.Truncate(it.Title, 90))
	}
	if it.Change != "new" {
		line += " _(updated: " + escape(textx.Truncate(it.Change, 60)) + ")_"
	}
	out := []string{line}
	if it.Action != "" {
		out = append(out, "      ↳ "+escape(textx.Truncate(it.Action, 160)))
	}
	return out
}

// scopeList names tenant environments compactly, tenants in order of
// appearance: "acme: prod, stage; beta: prod".
func scopeList(scopes [][2]string) string {
	var tenants []string
	envs := map[string][]string{}
	for _, s := range scopes {
		if _, ok := envs[s[0]]; !ok {
			tenants = append(tenants, s[0])
		}
		if !slices.Contains(envs[s[0]], s[1]) {
			envs[s[0]] = append(envs[s[0]], s[1])
		}
	}
	parts := make([]string, len(tenants))
	for i, t := range tenants {
		parts[i] = t + ": " + strings.Join(envs[t], ", ")
	}
	return strings.Join(parts, "; ")
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// countLine renders ":red_circle: 1  :large_orange_circle: 57 …", skipping zeros.
func countLine(cs []report.PriorityCount) string {
	var parts []string
	for _, c := range cs {
		if c.Count > 0 {
			parts = append(parts, prioEmoji[c.Priority]+" "+strconv.Itoa(c.Count))
		}
	}
	return strings.Join(parts, "   ")
}

// alert is one P1 finding learned in this run: new or updated, or found by
// a full-history check; or one card listing many found by the check.
type alert struct {
	id, text string
	count    int // P1 findings on the card
	blocks   func(dash string, maxText int) []slack.Block
}

// maxHistoryCards is how many P1 findings of a full-history check get a card
// each; above it (a new tenant, a lost state) one card lists them all.
// New and updated P1 findings always get their own card.
const maxHistoryCards = 5

func p1Alerts(r report.Report) []alert {
	var out []alert
	for _, it := range r.Items() {
		if it.Priority != "P1" {
			continue
		}
		it := it
		label := report.Label(it.ID, it.Title)
		out = append(out, alert{
			id:    it.ID,
			text:  "P1: " + report.Named(it.Scope, it.Product) + " " + label,
			count: 1,
			blocks: func(dash string, maxText int) []slack.Block {
				note := "new"
				if it.Change != "new" {
					note = "updated: " + it.Change // escaped with the context line
				}
				return alertCard(card{
					id: it.ID, title: it.Title, link: first(it.Links), advisories: it.Advisories, product: report.Named(it.Scope, it.Product), constraint: it.Constraint,
					summary: it.Summary, action: it.Action, severity: it.Severity, cvss: it.CVSS, kev: it.KEV, epss: it.EPSS,
					redHat: it.RedHatSeverity, redHatStatement: it.RedHatStatement,
					fixed: it.Fixed, match: it.Match, noData: it.NoVersionData, note: note,
					packages: it.Packages, imageOnly: it.ImageOnly,
				}, dash, maxText)
			},
		})
	}
	history := slices.DeleteFunc(slices.Clone(r.Open), func(it report.OpenItem) bool { return it.Priority != "P1" || !it.FirstSeen })
	if len(history) > maxHistoryCards {
		return append(out, historyAlert(history))
	}
	for _, it := range history {
		out = append(out, alert{
			id:    it.ID,
			text:  "P1: " + report.Named(it.Scope, it.Product) + " " + report.Label(it.ID, it.Title),
			count: 1,
			blocks: func(dash string, maxText int) []slack.Block {
				return alertCard(card{
					id: it.ID, title: it.Title, link: it.Link, advisories: it.Advisories, product: report.Named(it.Scope, it.Product), constraint: it.Constraint,
					summary: it.Summary, action: historyAction(it), severity: it.Severity, cvss: it.CVSS, kev: it.KEV, epss: it.EPSS,
					fixed: it.Fixed, match: it.Match, noData: it.NoVersionData,
					packages: it.Packages, imageOnly: it.ImageOnly,
					note: "found by the full-history check: this advisory is older, but the version we run is affected",
				}, dash, maxText)
			},
		})
	}
	return out
}

// historyAction is Claude's action, else a generic one from the fixes.
func historyAction(it report.OpenItem) string {
	switch {
	case it.Action != "":
		return it.Action
	case len(it.Fixed) > 0:
		return "Upgrade to a fixed version: " + strings.Join(it.Fixed, ", ") + "."
	}
	return "No fix released yet: check the advisory for mitigations."
}

// historyAlert is one card for many P1 findings of full-history checks:
// one line per advisory and product (ID, product, scopes, version,
// action), as many as fit, the rest counted.
func historyAlert(items []report.OpenItem) alert {
	type key struct{ id, product, constraint, action string }
	type group struct {
		it     report.OpenItem
		scopes [][2]string
	}
	idx := map[key]*group{}
	var groups []*group
	for _, it := range items {
		k := key{it.ID, it.Product, it.Constraint, historyAction(it)}
		g := idx[k]
		if g == nil {
			g = &group{it: it}
			idx[k] = g
			groups = append(groups, g)
		}
		if it.Scope != "" {
			g.scopes = append(g.scopes, [2]string{it.Tenant, it.Environment})
		}
	}
	n := len(items)
	what := fmt.Sprintf("%d P1 findings from the full-history check", n)
	return alert{
		id:    "full-history",
		text:  "P1: " + what,
		count: n,
		blocks: func(dash string, maxText int) []slack.Block {
			head := []string{"These advisories are older, but the versions we run are affected. Listed on one card instead of one card each."}
			var lines [][]string
			for _, g := range groups {
				it := g.it
				link := it.Link
				if len(it.Advisories) > 0 {
					link = it.Advisories[0].URL
				}
				name := "*" + escape(it.Product) + "*"
				switch {
				case len(g.scopes) == 1:
					name = "*" + escape(report.Named(it.Scope, it.Product)) + "*"
				case len(g.scopes) > 1:
					name += " (" + escape(scopeList(g.scopes)) + ")"
				}
				exploit := ""
				if it.KEV {
					exploit = " · :warning: KEV"
				}
				lines = append(lines, []string{
					fmt.Sprintf("%s %s · %s `%s`%s", prioEmoji["P1"], idLink(it.ID, it.Title, link), name, escape(versions(it.Constraint)), exploit),
					"      ↳ " + escape(textx.Truncate(historyAction(it), 160)),
				})
			}
			var text string
			for k := len(lines); k >= 0; k-- {
				all := slices.Clone(head)
				for _, l := range lines[:k] {
					all = append(all, l...)
				}
				if k < len(lines) {
					all = append(all, fmt.Sprintf("      _+%d more on the dashboard_", len(lines)-k))
				}
				if text = strings.Join(all, "\n"); utf8.RuneCountInString(text) <= maxText {
					break
				}
			}
			ctx := []string{"found by the full-history check"}
			if dash != "" {
				ctx = append(ctx, "<"+dash+"|:bar_chart: dashboard>")
			}
			return []slack.Block{
				slack.NewHeaderBlock(plain(textx.Truncate(":rotating_light: "+what, maxHeaderText))),
				slack.NewSectionBlock(mrkdwn(truncate(text, maxText)), nil, nil),
				slack.NewContextBlock("", mrkdwn(strings.Join(ctx, "  ·  "))),
			}
		},
	}
}

type card struct {
	id, title, link, product, constraint string
	summary, action, severity, match     string
	redHat, redHatStatement              string
	cvss, epss                           float64
	kev, noData                          bool
	fixed                                []string
	advisories                           []report.Advisory
	note                                 string
	packages                             []finding.Package
	imageOnly                            bool
}

// alertCard renders one critical finding: what, where, how bad, what to do.
func alertCard(c card, dash string, maxText int) []slack.Block {
	header := ":rotating_light: P1 · " + c.product + " · " + report.Label(c.id, c.title)

	var text strings.Builder
	fmt.Fprintf(&text, "%s  ·  *%s* `%s`", idLinks(c), escape(c.product), escape(versions(c.constraint)))
	if c.title != "" && report.Label(c.id, c.title) == c.id {
		text.WriteString("\n*" + escape(c.title) + "*")
	}
	if c.summary != "" && c.summary != c.title {
		text.WriteString("\n" + escape(c.summary))
	}
	if len(c.packages) > 0 {
		label := "Confirmed in running images"
		if c.imageOnly {
			label = "In running images (no advisory for the product)"
		}
		text.WriteString("\n:package: *" + label + ":* " + escape(report.PackageLine(c.packages, 2)))
	}
	if c.action != "" {
		text.WriteString("\n:point_right: *" + escape(c.action) + "*")
	}
	if c.redHatStatement != "" {
		text.WriteString("\n_Red Hat:_ " + escape(textx.Truncate(c.redHatStatement, 400)))
	}

	sev := escape(severityLabel(c.severity))
	if c.cvss > 0 {
		sev += fmt.Sprintf(" · CVSS %.1f", c.cvss)
	}
	if c.redHat != "" {
		sev += "\nRed Hat: " + escape(c.redHat)
	}
	fixed := "no fix released yet"
	switch {
	case len(c.fixed) > 0:
		fixed = fixedIn(c.constraint, c.fixed)
	case c.imageOnly && c.packages[0].Fixed != "":
		fixed = c.packages[0].Name + " " + c.packages[0].Fixed
	}
	var exploit []string
	if c.kev {
		exploit = append(exploit, ":warning: exploited in the wild (CISA KEV)")
	}
	if c.epss > 0 {
		exploit = append(exploit, fmt.Sprintf("EPSS %.1f%% (probability in 30 days)", c.epss*100))
	}
	if len(exploit) == 0 {
		exploit = []string{"no known exploitation"}
	}
	fields := []*slack.TextBlockObject{
		mrkdwn("*Severity*\n" + sev),
		mrkdwn("*Fixed in*\n" + escape(textx.Truncate(fixed, 500))), // a field holds 2000
		mrkdwn("*Exploitation*\n" + strings.Join(exploit, "\n")),
		mrkdwn("*Our version*\n" + matchLabel(c.match, c.noData)),
	}
	ctx := []string{escape(c.note)}
	if dash != "" {
		ctx = append(ctx, "<"+dash+"|:bar_chart: dashboard>")
	}
	return []slack.Block{
		slack.NewHeaderBlock(plain(textx.Truncate(header, maxHeaderText))),
		slack.NewSectionBlock(mrkdwn(truncate(text.String(), maxText)), fields, nil),
		slack.NewContextBlock("", mrkdwn(strings.Join(ctx, "  ·  "))),
	}
}

// fixedIn leads with the version to upgrade to from the one we run
// (match.UpgradeTarget; per alternative of a union constraint), followed by
// the other fixed versions: "26.1.4 (also 25.0.9)".
func fixedIn(constraint string, fixed []string) string {
	all := strings.Join(fixed, ", ")
	c, err := match.ParseConstraint(constraint)
	if err != nil || c.Any() {
		return all
	}
	alts := c.Alternatives()
	var lead, targets []string
	for _, alt := range alts {
		target, _ := match.UpgradeTarget(alt, [][]string{fixed})
		if target == "" {
			continue
		}
		targets = append(targets, target)
		if len(alts) == 1 {
			lead = append(lead, target)
		} else {
			lead = append(lead, alt.String()+" → "+target)
		}
	}
	if len(lead) == 0 {
		return all
	}
	out := strings.Join(lead, ", ")
	if rest := slices.DeleteFunc(slices.Clone(fixed), func(v string) bool { return slices.Contains(targets, v) }); len(rest) > 0 {
		out += " (also " + strings.Join(rest, ", ") + ")"
	}
	return out
}

// idLinks names the advisory and links its NVD and GitHub pages
// ("*CVE-2026-1* · NVD · GitHub"); without them the ID links its first
// reference.
func idLinks(c card) string {
	if len(c.advisories) == 0 {
		return idLink(c.id, c.title, c.link)
	}
	parts := []string{"*" + escape(report.Label(c.id, c.title)) + "*"}
	for _, a := range c.advisories {
		label := a.Source
		if a.ID != c.id {
			label += " " + a.ID
		}
		parts = append(parts, linkTo(a.URL, label))
	}
	return strings.Join(parts, " · ")
}

// idLink links an advisory to its first reference when there is one; feed
// items whose ID is a URL show their title.
func idLink(id, title, link string) string {
	label := report.Label(id, title)
	if link == "" && label != id {
		link = id
	}
	return "*" + linkTo(link, label) + "*"
}

// linkTo is the only place advisory-derived URLs become Slack markup
// (<url|label>). URLs come from NVD, OSV and feeds: only https URLs
// without markup characters (< > |), whitespace or control characters are
// linked, anything else shows the plain label. The label is escaped.
func linkTo(link, label string) string {
	if !safeURL(link) {
		return escape(label)
	}
	return "<" + link + "|" + escape(label) + ">"
}

func safeURL(link string) bool {
	if !strings.HasPrefix(link, "https://") || strings.ContainsAny(link, "<>|") {
		return false
	}
	if strings.ContainsFunc(link, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return false
	}
	u, err := url.Parse(link)
	return err == nil && u.Host != ""
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// versions shows a union constraint ("26.7.0 || 20.0.3") as a list.
func versions(constraint string) string {
	return strings.ReplaceAll(constraint, " || ", ", ")
}

func severityLabel(s string) string {
	if s == "" || s == "unknown" {
		return "not rated yet"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func matchLabel(m string, noData bool) string {
	switch {
	case m == "affected":
		return "affected"
	case m == "not_affected":
		return "not affected"
	case noData:
		return "unknown: the advisory lists no versions"
	}
	return "depends on exact version"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// plain is plain text with emoji shortcodes rendered (":shield:" -> 🛡).
func plain(s string) *slack.TextBlockObject {
	return slack.NewTextBlockObject(slack.PlainTextType, s, true, false)
}
func mrkdwn(s string) *slack.TextBlockObject {
	return slack.NewTextBlockObject(slack.MarkdownType, s, false, false)
}

// escape applies Slack's required mrkdwn escaping.
func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// truncate shortens mrkdwn text to at most n runes at a word boundary
// (textx.Truncate), never inside link or mention markup (<url|label>):
// a cut there would leave the markup open.
func truncate(s string, n int) string {
	out := textx.Truncate(s, n)
	if out == s {
		return s
	}
	body := strings.TrimSuffix(out, "…")
	if lt := strings.LastIndex(body, "<"); lt > strings.LastIndex(body, ">") {
		body = strings.TrimRight(body[:lt], " ")
	}
	return body + "…"
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// baselineReasons counts the full-history checks by reason, e.g.
// "2 new, 1 version changed".
func baselineReasons(bs []report.BaselineSummary) string {
	n := map[string]int{}
	for _, b := range bs {
		n[b.Reason]++
	}
	var parts []string
	for _, r := range []string{report.BaselineNew, report.BaselineVersionChanged, report.BaselineSourcesChanged, report.BaselineMatching, report.BaselineBootstrap} {
		if n[r] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[r], r))
		}
	}
	return strings.Join(parts, ", ")
}
