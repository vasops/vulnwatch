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
		p1 := p1Total(alerts)
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
			attrs := []any{"kind", "p1_alert", "channel", rt.alert, "id", a.id, "text", a.text}
			if len(a.scopes) > 0 {
				attrs = append(attrs, "scopes", report.ScopeList(a.scopes))
			}
			logx.Audit(ctx, o.log, "slack message posted", attrs...)
		}
		if w := sub.Weekly; w != nil && ctx.Err() == nil {
			if err := o.post(ctx, rt.channel, weeklyText(w), weeklyBlocks(w, rt.weeklyTitle(), dash, o.maxText())); err != nil {
				errs = append(errs, fmt.Errorf("slack weekly %s: %w", rt.channel, err))
			} else {
				logx.Audit(ctx, o.log, "slack message posted", "kind", "weekly", "channel", rt.channel, "scopes", strings.TrimPrefix(rt.title, " · "),
					"text", weeklyText(w))
			}
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
	if c := report.Count(report.Findings(r.Items())); c.Findings > 0 {
		text = fmt.Sprintf("vulnwatch: %d new or updated %s%s", c.Findings, plural(c.Findings, "vulnerability", "vulnerabilities"), inEnvironments(c.Findings, c.Scopes))
	}
	if n := sum(r.CurrentOpenCounts()); n > 0 {
		text += fmt.Sprintf(", %d open", n)
	}
	return text
}

// inEnvironments is " in M environments" when the findings span more
// environments than there are findings (N findings, M environments), else "".
func inEnvironments(findings, scopes int) string {
	if scopes > findings {
		return fmt.Sprintf(" in %d environments", scopes)
	}
	return ""
}

func sum(cs []report.PriorityCount) int {
	n := 0
	for _, c := range cs {
		n += c.Count
	}
	return n
}

// triageFailureLine says how many findings Claude gave no verdict for and
// why; they keep the rule-based priority until a later run asks again.
func triageFailureLine(r report.Report) string {
	why := ""
	if r.TriageFailure != "" {
		why = " (" + r.TriageFailure + ")"
	}
	n := r.TriageUntriaged
	if n == 0 {
		return fmt.Sprintf(":warning: Claude triage failed in %d %s%s", r.TriageFailures, plural(r.TriageFailures, "batch", "batches"), why)
	}
	return fmt.Sprintf(":warning: Claude gave no verdict for %d %s%s: rule-based priority until a later run asks again",
		n, plural(n, "finding", "findings"), why)
}

// summaryBlocks is the per-run message: counts, one section per finding and
// where to look. failed names the sources that failed in the run (for every
// route; the warning count only where the run's warnings are kept).
// A section per finding keeps a long one from pushing out the others.
func summaryBlocks(r report.Report, scopes, dash string, p1 p1Count, alertChannel string, failed []string, maxText int) []slack.Block {
	title := ":shield: vulnwatch report" + scopes + " · " + r.Until.Format("2 Jan 2006")
	if r.Mode != report.ModeRun {
		title += " (" + r.Mode + ")"
	}
	var head, tail []string
	if p1.findings > 0 {
		head = append(head, fmt.Sprintf(":rotating_light: *%d critical (P1) %s%s*, see <#%s>", p1.findings, plural(p1.findings, "finding", "findings"), inEnvironments(p1.findings, p1.scopes), alertChannel))
	}
	if r.TriageFailures > 0 { // run-wide: on every route
		head = append(head, triageFailureLine(r))
	}
	findings := report.Findings(r.Items())
	counts := report.Count(findings)
	newLine := "*New:* none"
	if counts.Findings > 0 {
		newLine = fmt.Sprintf("*New:* %d%s   %s", counts.Findings, inEnvironments(counts.Findings, counts.Scopes), countLine(counts.ByPriority))
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
	blocks := []slack.Block{
		slack.NewHeaderBlock(plain(textx.Truncate(title, maxHeaderText))),
		slack.NewSectionBlock(mrkdwn(truncate(strings.Join(head, "\n"), maxText)), nil, nil),
	}
	for _, f := range findings[:min(len(findings), maxSummaryItems)] {
		blocks = append(blocks, slack.NewSectionBlock(mrkdwn(summaryEntry(f, maxText)), nil, nil))
	}
	if len(findings) > maxSummaryItems {
		blocks = append(blocks, slack.NewSectionBlock(mrkdwn(fmt.Sprintf("_+%d more on the dashboard_", len(findings)-maxSummaryItems)), nil, nil))
	}
	return append(blocks,
		slack.NewSectionBlock(mrkdwn(truncate(strings.Join(tail, "\n"), maxText)), nil, nil),
		slack.NewContextBlock("", mrkdwn(strings.Join(ctx, "  ·  "))),
	)
}

const (
	// maxSummaryItems is how many new findings the summary lists.
	maxSummaryItems = 10
	// maxEntryTitle and maxEntryAction cut a finding's title and action in
	// the summary.
	maxEntryTitle  = 500
	maxEntryAction = 500
	// scopeIndent starts the action and scope lines under a finding's first line.
	scopeIndent = "      "
)

// summaryEntry is one finding as listed in the summary: priority, name and
// ID, the advisory title, the action, and one line per affected line (who,
// which version). It stays within maxText runes: scope lines that do not fit
// are replaced by "+N more environments".
func summaryEntry(f report.Finding[report.Item], maxText int) string {
	it := f.Representative
	link := ""
	for _, a := range it.Advisories {
		link = a.URL
		break
	}
	link = cmpOr(link, first(it.Links))
	id := idLink(it.ID, it.Title, link)
	title := ""
	if it.Title != "" && report.Label(it.ID, it.Title) == it.ID {
		title = escape(textx.Truncate(it.Title, min(maxEntryTitle, maxText/3)))
	}
	var head []string
	var lines []report.Line
	switch {
	case len(f.Lines) == 0 || len(f.Scopes) == 1 && len(f.Lines) == 1:
		// One line, title after the ID.
		name, constraint := it.Product, it.Constraint
		if len(f.Lines) == 1 {
			name, constraint = report.Named(it.Scope, it.Product), f.Lines[0].Constraint
		}
		line := fmt.Sprintf("%s *%s* `%s` · %s", prioEmoji[f.Priority], escape(name), escape(versions(constraint)), id)
		if title != "" {
			line += " " + title
		}
		head = []string{line + changeNote(cmp.Or(f.Change, it.Change))}
	default:
		// The title gets its own line, the versions go on the scope lines.
		head = []string{prioEmoji[f.Priority] + " *" + escape(it.Product) + "* · " + id + changeNote(f.Change)}
		if title != "" {
			head = append(head, title)
		}
		lines = f.Lines
	}
	if f.Action != "" {
		head = append(head, scopeIndent+"↳ "+escape(textx.Truncate(f.Action, min(maxEntryAction, maxText/3))))
	}
	out := fitLines(head, lines, func(l report.Line) string { return affectedLine(l, f, scopeIndent+"• ") }, scopeIndent, maxText)
	return truncate(strings.Join(out, "\n"), maxText)
}

// changeNote is " _(updated: ...)_" for a change other than "new", escaped.
func changeNote(change string) string {
	if change == "" || change == "new" {
		return ""
	}
	return " _(updated: " + escape(textx.Truncate(change, 60)) + ")_"
}

// affectedLine is one affected line: who, which version. A line below the
// finding's priority leads with its own emoji; a line carries its own change
// when the finding's scopes differ in it.
func affectedLine[T any](l report.Line, f report.Finding[T], bullet string) string {
	s := bullet
	if e := prioEmoji[l.Priority]; l.Priority != f.Priority && e != "" {
		s += e + " "
	}
	s += escape(l.Names()) + " · `" + escape(versions(l.Constraint)) + "`"
	if f.Change == "" {
		s += changeNote(l.Change)
	}
	return s
}

// fitLines appends the rendered lines to head while the whole stays within
// budget runes, replacing the rest by one "+N more environments" line.
func fitLines(head []string, lines []report.Line, render func(report.Line) string, indent string, budget int) []string {
	rendered := make([]string, len(lines))
	for i, l := range lines {
		rendered[i] = render(l)
	}
	for k := len(lines); ; k-- {
		out := append(slices.Clone(head), rendered[:k]...)
		if k < len(lines) {
			n := distinctScopes(lines[k:])
			out = append(out, fmt.Sprintf("%s_+%d more %s_", indent, n, plural(n, "environment", "environments")))
		}
		if k == 0 || utf8.RuneCountInString(strings.Join(out, "\n")) <= budget {
			return out
		}
	}
}

func distinctScopes(lines []report.Line) int {
	seen := map[report.ScopeRef]struct{}{}
	for _, l := range lines {
		for _, s := range l.Scopes {
			seen[s] = struct{}{}
		}
	}
	return len(seen)
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
	count    int               // P1 findings on the card
	scopes   []report.ScopeRef // the tenant environments they were found in
	blocks   func(dash string, maxText int) []slack.Block
}

// p1Count is the P1 findings of a route and the environments they span.
type p1Count struct{ findings, scopes int }

func p1Total(alerts []alert) p1Count {
	var c p1Count
	var seen []report.ScopeRef
	for _, a := range alerts {
		c.findings += a.count
		for _, s := range a.scopes {
			if !slices.Contains(seen, s) {
				seen = append(seen, s)
			}
		}
	}
	c.scopes = len(seen)
	return c
}

// maxHistoryCards is how many P1 findings of a full-history check get a card
// each; above it (a new tenant, a lost state) one card lists them all.
// New and updated P1 findings always get their own card.
const maxHistoryCards = 5

// p1Alerts is one card per P1 finding of the route, not one per scope: the
// scopes where the finding is P1 are its affected lines.
func p1Alerts(r report.Report) []alert {
	var out []alert
	var p1 []report.Item
	for _, it := range r.Items() {
		if it.Priority == "P1" {
			p1 = append(p1, it)
		}
	}
	for _, f := range report.Findings(p1) {
		it := f.Representative
		name, affected, envs := cardScope(f, it.Scope, it.Product)
		out = append(out, alert{
			id:     it.ID,
			text:   "P1: " + name + " " + report.Label(it.ID, it.Title) + environmentCount(envs, " (", ")"),
			count:  1,
			scopes: f.Scopes,
			blocks: func(dash string, maxText int) []slack.Block {
				note := "new"
				switch {
				case f.Change == "":
					note = "updated: the change differs per environment, see Affected"
				case f.Change != "new":
					note = "updated: " + f.Change // escaped with the context line
				}
				return alertCard(card{
					id: it.ID, title: it.Title, link: first(it.Links), advisories: it.Advisories, product: name, constraint: it.Constraint,
					summary: it.Summary, action: f.Action, severity: it.Severity, cvss: it.CVSS, kev: it.KEV, epss: it.EPSS,
					redHat: it.RedHatSeverity, redHatStatement: it.RedHatStatement,
					fixed: it.Fixed, match: it.Match, noData: it.NoVersionData, note: note,
					packages: it.Packages, imageOnly: it.ImageOnly,
					affected: affected, environments: envs,
				}, dash, maxText)
			},
		})
	}
	history := slices.DeleteFunc(slices.Clone(r.Open), func(it report.OpenItem) bool { return it.Priority != "P1" || !it.FirstSeen })
	findings := report.OpenFindings(history, historyAction)
	if len(findings) > maxHistoryCards {
		return append(out, historyAlert(findings))
	}
	for _, f := range findings {
		it := f.Representative
		name, affected, envs := cardScope(f, it.Scope, it.Product)
		out = append(out, alert{
			id:     it.ID,
			text:   "P1: " + name + " " + report.Label(it.ID, it.Title) + environmentCount(envs, " (", ")"),
			count:  1,
			scopes: f.Scopes,
			blocks: func(dash string, maxText int) []slack.Block {
				return alertCard(card{
					id: it.ID, title: it.Title, link: it.Link, advisories: it.Advisories, product: name, constraint: it.Constraint,
					summary: it.Summary, action: f.Action, severity: it.Severity, cvss: it.CVSS, kev: it.KEV, epss: it.EPSS,
					fixed: it.Fixed, match: it.Match, noData: it.NoVersionData,
					packages: it.Packages, imageOnly: it.ImageOnly,
					note:     "found by the full-history check: this advisory is older, but the version we run is affected",
					affected: affected, environments: envs,
				}, dash, maxText)
			},
		})
	}
	return out
}

// cardScope names what a card shows of the finding's scopes. One scope on
// one line keeps the scoped product name and the version fields; otherwise
// the product is bare and the card lists the affected lines.
func cardScope[T any](f report.Finding[T], scope, product string) (name, affected string, environments int) {
	if len(f.Scopes) == 1 && len(f.Lines) == 1 {
		return report.Named(scope, product), "", 0
	}
	return product, affectedList(f), len(f.Scopes)
}

// environmentCount is "<before>N environments<after>" when N > 1, else "".
func environmentCount(n int, before, after string) string {
	if n > 1 {
		return fmt.Sprintf("%s%d environments%s", before, n, after)
	}
	return ""
}

// maxAffectedText keeps the Affected field of a card within Slack's 2000
// characters for a field.
const maxAffectedText = 1900

// affectedList is the card's Affected field: one line per affected line,
// "" for a finding without tenants (the card then shows our version).
func affectedList[T any](f report.Finding[T]) string {
	if len(f.Lines) == 0 {
		return ""
	}
	return strings.Join(fitLines(nil, f.Lines, func(l report.Line) string { return affectedLine(l, f, "• ") }, "", maxAffectedText), "\n")
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

// maxHistoryEntryText keeps one finding's scope lines on the history card
// from taking the room of the others.
const maxHistoryEntryText = 600

// historyAlert is one card for many P1 findings of full-history checks:
// one entry per finding (ID, product, action) with its affected lines, as
// many as fit, the rest counted.
func historyAlert(findings []report.Finding[report.OpenItem]) alert {
	n := len(findings)
	var scopes []report.ScopeRef
	for _, f := range findings {
		for _, s := range f.Scopes {
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	what := fmt.Sprintf("%d P1 findings from the full-history check", n)
	return alert{
		id:     "full-history",
		text:   "P1: " + what,
		count:  n,
		scopes: scopes,
		blocks: func(dash string, maxText int) []slack.Block {
			head := []string{"These advisories are older, but the versions we run are affected. Listed on one card instead of one card each."}
			var lines [][]string
			for _, f := range findings {
				it := f.Representative
				link := it.Link
				if len(it.Advisories) > 0 {
					link = it.Advisories[0].URL
				}
				exploit := ""
				if it.KEV {
					exploit = " · :warning: KEV"
				}
				var head1 string
				var scoped []report.Line
				if len(f.Lines) == 0 || len(f.Scopes) == 1 && len(f.Lines) == 1 {
					name, constraint := it.Product, it.Constraint
					if len(f.Lines) == 1 {
						name, constraint = report.Named(it.Scope, it.Product), f.Lines[0].Constraint
					}
					head1 = fmt.Sprintf("%s %s · *%s* `%s`%s", prioEmoji["P1"], idLink(it.ID, it.Title, link), escape(name), escape(versions(constraint)), exploit)
				} else {
					head1 = fmt.Sprintf("%s %s · *%s*%s", prioEmoji["P1"], idLink(it.ID, it.Title, link), escape(it.Product), exploit)
					scoped = f.Lines
				}
				entry := []string{head1, scopeIndent + "↳ " + escape(textx.Truncate(f.Action, 160))}
				lines = append(lines, fitLines(entry, scoped, func(l report.Line) string { return affectedLine(l, f, scopeIndent+"• ") }, scopeIndent, maxHistoryEntryText))
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
	affected                             string // the Affected list; empty without tenants
	environments                         int
}

// alertCard renders one critical finding: what, where, how bad, what to do.
func alertCard(c card, dash string, maxText int) []slack.Block {
	header := ":rotating_light: P1 · " + c.product + " · " + report.Label(c.id, c.title) + environmentCount(c.environments, " · ", "")

	var text strings.Builder
	fmt.Fprintf(&text, "%s  ·  *%s*", idLinks(c), escape(c.product))
	if c.affected == "" { // with an Affected list the versions are on its lines
		fmt.Fprintf(&text, " `%s`", escape(versions(c.constraint)))
	}
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
	}
	if c.affected != "" {
		fields = append(fields, mrkdwn("*Affected*\n"+c.affected))
	} else {
		fields = append(fields, mrkdwn("*Our version*\n"+matchLabel(c.match, c.noData)))
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
