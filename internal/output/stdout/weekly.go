package stdout

import (
	"fmt"
	"strings"

	"github.com/vasops/vulnwatch/internal/report"
)

// weekly prints the weekly report: the same parts as the Slack message,
// every finding listed.
func (o *Output) weekly(b *strings.Builder, w *report.Weekly) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	fresh := report.OpenFindings(w.New, func(it report.OpenItem) string { return it.Action })
	closed := report.ClosedFindings(w.Closed)
	longest := report.OpenFindings(w.Oldest, actionOf)
	nf, nc := report.Count(fresh), report.Count(closed)
	open := 0
	var counts []string
	for _, c := range w.OpenCounts {
		open += c.Count
		counts = append(counts, fmt.Sprintf("%s %d", c.Priority, c.Count))
	}

	p("\n%s\n", o.c(bold, "== Weekly report · "+w.Days()+" =="))
	if open == 0 && len(fresh) == 0 && len(closed) == 0 {
		p("Nothing open. Nothing new or closed this week.\n")
		return
	}
	p("Open: %d (%s)\n", open, strings.Join(counts, " · "))
	p("New this week: %d%s · Closed this week: %d%s\n", nf.Findings, inEnvironments(nf), nc.Findings, inEnvironments(nc))
	if len(fresh) > 0 {
		p("\n%s\n", o.c(bold, "New this week"))
		for _, f := range fresh {
			it := f.Representative
			p("  %s %s %s%s\n", o.c(prioColor[f.Priority], f.Priority), it.Product, o.c(bold, it.ID), titleOf(it.ID, it.Title))
			o.scopes(b, f.Scopes)
		}
	}
	if len(closed) > 0 {
		p("\n%s\n", o.c(bold, "Closed this week"))
		for _, f := range closed {
			it := f.Representative
			reason := ""
			if f.Change != "" {
				reason = " · " + report.ClosedReasons[f.Change]
			}
			p("  %s %s%s%s\n", it.Product, o.c(bold, it.ID), reason, titleOf(it.ID, it.Title))
			if f.Change != "" {
				o.scopes(b, f.Scopes)
				continue
			}
			for _, l := range f.Lines {
				p("      %s\n", o.c(dim, l.Names()+" · "+report.ClosedReasons[l.Change]))
			}
		}
	}
	if len(longest) > 0 {
		p("\n%s\n", o.c(bold, "Open the longest"))
		for _, f := range longest {
			it := f.Representative
			days, unit := w.DaysOpen(f.Product, f.ID), "days"
			if days == 1 {
				unit = "day"
			}
			p("  %s %s %s · %d %s%s\n", o.c(prioColor[f.Priority], f.Priority), it.Product, o.c(bold, it.ID), days, unit, titleOf(it.ID, it.Title))
			if f.Action != "" {
				p("      Action: %s\n", f.Action)
			}
			o.scopes(b, f.Scopes)
		}
	}
}

func (o *Output) scopes(b *strings.Builder, scopes []report.ScopeRef) {
	if len(scopes) > 0 {
		fmt.Fprintf(b, "      %s\n", o.c(dim, report.ScopeList(scopes)))
	}
}

// titleOf is "  title", or "" when the label already is the title.
func titleOf(id, title string) string {
	if title == "" || report.Label(id, title) != id {
		return ""
	}
	return "  " + title
}

// inEnvironments is " in M environments" when the findings span more
// environments than there are findings.
func inEnvironments(c report.Counts) string {
	if c.Scopes > c.Findings {
		return fmt.Sprintf(" in %d environments", c.Scopes)
	}
	return ""
}

// actionOf is the action shown for a finding open the longest, as in
// Slack: Claude's, else one from the fixes.
func actionOf(it report.OpenItem) string {
	switch {
	case it.Action != "":
		return it.Action
	case len(it.Fixed) > 0:
		return "Upgrade to a fixed version: " + strings.Join(it.Fixed, ", ") + "."
	}
	return "No fix released yet: check the advisory for mitigations."
}
