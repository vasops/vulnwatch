package slack

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/slack-go/slack"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/textx"
)

const (
	// maxWeeklyItems is how many findings "New" and "Closed" list.
	maxWeeklyItems = 10
	// maxWeeklyText cuts a title or action in the weekly report.
	maxWeeklyText = 200
	// maxWeeklyEntryText keeps one finding's lines from taking the room of
	// the others in its section.
	maxWeeklyEntryText = 600
)

// weeklyFindings is the weekly report grouped like the daily summary.
type weeklyFindings struct {
	open             int
	fresh, longest   []report.Finding[report.OpenItem]
	closed           []report.Finding[report.ClosedItem]
	freshCount, gone report.Counts
}

func groupWeekly(w *report.Weekly) weeklyFindings {
	g := weeklyFindings{
		open:    sum(w.OpenCounts),
		fresh:   report.OpenFindings(w.New, func(it report.OpenItem) string { return it.Action }),
		longest: report.OpenFindings(w.Oldest, historyAction),
		closed:  report.ClosedFindings(w.Closed),
	}
	g.freshCount, g.gone = report.Count(g.fresh), report.Count(g.closed)
	return g
}

// weeklyTitle names the route in the weekly header: the tenant when the
// route serves one, else the summary's title (none on the default route).
func (rt route) weeklyTitle() string {
	if rt.tenant != "" {
		return " · " + rt.tenant
	}
	return rt.title
}

// weeklyText is the notification / fallback text.
func weeklyText(w *report.Weekly) string {
	g := groupWeekly(w)
	return fmt.Sprintf("vulnwatch weekly: %d open, %d new, %d closed", g.open, g.freshCount.Findings, g.gone.Findings)
}

// weeklyBlocks is the weekly report of one route: counts, then a section
// each for the new, the closed and the longest open findings.
func weeklyBlocks(w *report.Weekly, scopes, dash string, maxText int) []slack.Block {
	g := groupWeekly(w)
	blocks := []slack.Block{
		slack.NewHeaderBlock(plain(textx.Truncate(":calendar: vulnwatch weekly"+scopes+" · "+w.Days(), maxHeaderText))),
	}
	if g.open == 0 && len(g.fresh) == 0 && len(g.closed) == 0 {
		blocks = append(blocks, slack.NewSectionBlock(mrkdwn("Nothing open. Nothing new or closed this week."), nil, nil))
	} else {
		open := fmt.Sprintf("*Open:* %d", g.open)
		if c := countLine(w.OpenCounts); c != "" {
			open += "   " + c
		}
		moved := fmt.Sprintf("*New this week:* %d%s · *Closed this week:* %d%s",
			g.freshCount.Findings, inEnvironments(g.freshCount.Findings, g.freshCount.Scopes),
			g.gone.Findings, inEnvironments(g.gone.Findings, g.gone.Scopes))
		blocks = append(blocks, slack.NewSectionBlock(mrkdwn(open+"\n"+moved), nil, nil))
	}
	var entries [][]string
	for _, f := range g.fresh {
		entries = append(entries, newEntry(f, maxText))
	}
	blocks = appendSection(blocks, "New this week", entries, maxWeeklyItems, maxText)
	entries = nil
	for _, f := range g.closed {
		entries = append(entries, closedEntry(f, maxText))
	}
	blocks = appendSection(blocks, "Closed this week", entries, maxWeeklyItems, maxText)
	entries = nil
	for _, f := range g.longest {
		entries = append(entries, oldestEntry(f, w.DaysOpen(f.Product, f.ID), maxText))
	}
	blocks = appendSection(blocks, "Open the longest", entries, report.MaxOldest, maxText)
	if dash != "" {
		blocks = append(blocks, slack.NewContextBlock("", mrkdwn("<"+dash+"|:bar_chart: Open the dashboard>")))
	}
	return blocks
}

// appendSection adds one section: a bold title and up to limit entries, as
// many as fit in maxText, the rest counted. Nothing for no entries.
func appendSection(blocks []slack.Block, title string, entries [][]string, limit, maxText int) []slack.Block {
	if len(entries) == 0 {
		return blocks
	}
	var text string
	for k := min(len(entries), limit); k >= 0; k-- {
		all := []string{"*" + title + "*"}
		for _, e := range entries[:k] {
			all = append(all, e...)
		}
		if k < len(entries) {
			all = append(all, fmt.Sprintf("_+%d more on the dashboard_", len(entries)-k))
		}
		if text = strings.Join(all, "\n"); utf8.RuneCountInString(text) <= maxText {
			break
		}
	}
	return append(blocks, slack.NewSectionBlock(mrkdwn(truncate(text, maxText)), nil, nil))
}

// weeklyHead is "<prefix>*product* · ID<suffix>  title", escaped once.
func weeklyHead(prefix, product, id, title, link, suffix string) string {
	s := prefix + "*" + escape(product) + "* · " + idLink(id, title, link) + suffix
	if title != "" && report.Label(id, title) == id {
		s += "  " + escape(textx.Truncate(title, maxWeeklyText))
	}
	return s
}

func advisoryLink(as []report.Advisory, link string) string {
	if len(as) > 0 {
		return as[0].URL
	}
	return link
}

// tenantLines is one line per tenant with its environments.
func tenantLines(scopes []report.ScopeRef) []report.Line {
	var out []report.Line
	idx := map[string]int{}
	for _, s := range scopes {
		i, ok := idx[s.Tenant]
		if !ok {
			i = len(out)
			idx[s.Tenant] = i
			out = append(out, report.Line{})
		}
		out[i].Scopes = append(out[i].Scopes, s)
	}
	return out
}

// scopeLines fits the finding's environments under head.
func scopeLines(head []string, lines []report.Line, render func(report.Line) string, maxText int) []string {
	return fitLines(head, lines, render, scopeIndent, min(maxWeeklyEntryText, maxText))
}

func envLine(l report.Line) string { return scopeIndent + "• " + escape(l.Names()) }

func newEntry(f report.Finding[report.OpenItem], maxText int) []string {
	it := f.Representative
	head := weeklyHead(prioEmoji[f.Priority]+" ", it.Product, it.ID, it.Title, advisoryLink(it.Advisories, it.Link), "")
	return scopeLines([]string{head}, tenantLines(f.Scopes), envLine, maxText)
}

func closedEntry(f report.Finding[report.ClosedItem], maxText int) []string {
	it := f.Representative
	reason := ""
	lines, render := tenantLines(f.Scopes), envLine
	if f.Change != "" {
		reason = " · " + report.ClosedReasons[f.Change]
	} else {
		// The environments closed for different reasons: a line per reason.
		lines = f.Lines
		render = func(l report.Line) string { return envLine(l) + " · " + report.ClosedReasons[l.Change] }
	}
	head := weeklyHead("", it.Product, it.ID, it.Title, advisoryLink(it.Advisories, it.Link), reason)
	return scopeLines([]string{head}, lines, render, maxText)
}

func oldestEntry(f report.Finding[report.OpenItem], days, maxText int) []string {
	it := f.Representative
	head := []string{weeklyHead(prioEmoji[f.Priority]+" ", it.Product, it.ID, it.Title, advisoryLink(it.Advisories, it.Link),
		fmt.Sprintf(" · %d %s", days, plural(days, "day", "days")))}
	if f.Action != "" {
		head = append(head, scopeIndent+"↳ "+escape(textx.Truncate(f.Action, maxWeeklyText)))
	}
	return scopeLines(head, tenantLines(f.Scopes), envLine, maxText)
}
