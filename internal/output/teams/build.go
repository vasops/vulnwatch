package teams

import (
	"fmt"
	"strings"

	"github.com/vasops/vulnwatch/internal/report"
)

// message is what a Teams Workflows webhook accepts: an attachment list
// carrying one Adaptive Card.
// https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-reference
type message struct {
	Type        string       `json:"type"`
	Attachments []attachment `json:"attachments"`
}

type attachment struct {
	ContentType string       `json:"contentType"`
	Content     adaptiveCard `json:"content"`
}

// adaptiveCard is the card itself. Teams renders schema 1.6 and older, so
// the cards here target 1.5 and use nothing newer.
type adaptiveCard struct {
	Schema  string         `json:"$schema"`
	Type    string         `json:"type"`
	Version string         `json:"version"`
	Body    []cardElement  `json:"body,omitempty"`
	Actions []cardAction   `json:"actions,omitempty"`
	MSTeams *msTeamsConfig `json:"msteams,omitempty"`
}

// cardElement is one body element. The package needs two shapes only, a
// TextBlock and a FactSet, so they share a struct with omitempty fields
// rather than an interface per element type.
type cardElement struct {
	Type   string `json:"type"`
	Text   string `json:"text,omitempty"`
	Size   string `json:"size,omitempty"`
	Weight string `json:"weight,omitempty"`
	Color  string `json:"color,omitempty"`
	Wrap   bool   `json:"wrap,omitempty"`
	Facts  []fact `json:"facts,omitempty"`
}

type fact struct {
	Title string `json:"title"`
	Value string `json:"value"`
}

// cardAction is an Action.OpenUrl button. Of the actions an Adaptive Card
// defines, a webhook renders every one but Action.Submit; this package
// only ever opens the advisory page.
type cardAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// msTeamsConfig carries the Teams-specific card options; width full stops
// the card from being rendered in a narrow column.
type msTeamsConfig struct {
	Width string `json:"width,omitempty"`
}

// colorAttention is the Adaptive Card text color for anything P1: the
// format has no card-level accent color, so severity is carried by the
// heading instead of a card-level accent colour.
const colorAttention = "Attention"

const (
	messageType       = "message"
	cardContentType   = "application/vnd.microsoft.card.adaptive"
	cardSchema        = "http://adaptivecards.io/schemas/adaptive-card.json"
	cardType          = "AdaptiveCard"
	cardVersion       = "1.5"
	actionTypeOpenURL = "Action.OpenUrl"
)

// newCard starts an Adaptive Card with a heading, optionally coloured for a
// P1, and wraps it in the message envelope the webhook expects.
func newCard(title, text, titleColor string) message {
	body := []cardElement{{
		Type: "TextBlock", Text: title, Size: "Medium", Weight: "Bolder",
		Color: titleColor, Wrap: true,
	}}
	if text != "" {
		body = append(body, cardElement{Type: "TextBlock", Text: text, Wrap: true})
	}
	return message{
		Type: messageType,
		Attachments: []attachment{{
			ContentType: cardContentType,
			Content: adaptiveCard{
				Schema: cardSchema, Type: cardType, Version: cardVersion,
				Body: body, MSTeams: &msTeamsConfig{Width: "full"},
			},
		}},
	}
}

// card is the Adaptive Card inside m, for the builders to append to.
func (m *message) card() *adaptiveCard { return &m.Attachments[0].Content }

// addFacts appends a FactSet to the card body.
func (m *message) addFacts(facts []fact) {
	c := m.card()
	c.Body = append(c.Body, cardElement{Type: "FactSet", Facts: facts})
}

// p1Item is one P1 finding as presented on a card: the fields the task
// names (CVE, product, version, severity, CVSS, KEV/EPSS, fix, action)
// plus the advisory link for the Action.OpenUrl button.
type p1Item struct {
	ID         string
	Product    string
	Constraint string
	Severity   string
	CVSS       float64
	KEV        bool
	EPSS       float64
	Fixed      []string
	Action     string
	Link       string
}

// dashboardLink fills a Grafana URL template: {from} and {to} become now-30d
// and now (mirrors webhook.dashboardLink / slack.Output.dashboardLink).
// Empty tmpl: no link.
func dashboardLink(tmpl string) string {
	if tmpl == "" {
		return ""
	}
	return strings.NewReplacer("{from}", "now-30d", "{to}", "now").Replace(tmpl)
}

// targetURL is where a P1 alert goes: alert if set, else the main URL
// (mirrors webhook.targetURL).
func targetURL(main, alert string) string {
	if alert != "" {
		return alert
	}
	return main
}

// advisoryLink is the first advisory page URL, else the first non-empty of
// links (mirrors webhook.advisoryAndOtherLinks, first element only: the
// card carries a single Action.OpenUrl button, unlike the webhook's full
// link list).
func advisoryLink(advisories []report.Advisory, links []string) string {
	for _, a := range advisories {
		return a.URL
	}
	for _, l := range links {
		if l != "" {
			return l
		}
	}
	return ""
}

// openItemLink is advisoryLink for an OpenItem, which carries its one extra
// reference as Link rather than a slice (mirrors webhook.openItemLinks).
func openItemLink(it report.OpenItem) string {
	return advisoryLink(it.Advisories, []string{it.Link})
}

// historyAction is the action text for a P1 found by a full-history check:
// Claude's action if it was triaged, else a generic one from the fixed
// versions (mirrors webhook.historyAction / slack.historyAction).
func historyAction(it report.OpenItem) string {
	switch {
	case it.Action != "":
		return it.Action
	case len(it.Fixed) > 0:
		return "Upgrade to a fixed version: " + strings.Join(it.Fixed, ", ") + "."
	}
	return "No fix released yet: check the advisory for mitigations."
}

// p1Items collects one item per P1 finding learned in this run: new or
// updated (r.Items()), plus every P1 first seen by a full-history check
// (r.Open, FirstSeen) — mirrors webhook.p1Payloads.
func p1Items(r report.Report) []p1Item {
	var out []p1Item
	for _, it := range r.Items() {
		if it.Priority != "P1" {
			continue
		}
		out = append(out, p1Item{
			ID: it.ID, Product: report.Named(it.Scope, it.Product), Constraint: it.Constraint,
			Severity: it.Severity, CVSS: it.CVSS, KEV: it.KEV, EPSS: it.EPSS, Fixed: it.Fixed,
			Action: it.Action, Link: advisoryLink(it.Advisories, it.Links),
		})
	}
	for _, it := range r.Open {
		if it.Priority != "P1" || !it.FirstSeen {
			continue
		}
		out = append(out, p1Item{
			ID: it.ID, Product: report.Named(it.Scope, it.Product), Constraint: it.Constraint,
			Severity: it.Severity, CVSS: it.CVSS, KEV: it.KEV, EPSS: it.EPSS, Fixed: it.Fixed,
			Action: historyAction(it), Link: openItemLink(it),
		})
	}
	return out
}

// countLine renders "P1: 1, P2: 57", skipping zeros; "none" when every
// priority is zero.
func countLine(cs []report.PriorityCount) string {
	var parts []string
	for _, c := range cs {
		if c.Count > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", c.Priority, c.Count))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func sumCounts(cs []report.PriorityCount) int {
	n := 0
	for _, c := range cs {
		n += c.Count
	}
	return n
}

func hasP1(cs []report.PriorityCount) bool {
	for _, c := range cs {
		if c.Priority == "P1" && c.Count > 0 {
			return true
		}
	}
	return false
}

// buildSummaryCard renders the run summary as one Adaptive Card: counts by
// priority, new/open totals, the dashboard link and the sources that
// failed — the same data as webhook.buildSummary / the Slack summary.
func buildSummaryCard(r report.Report, dashboard string) message {
	title := "vulnwatch report · " + r.Until.Format("2 Jan 2006")
	if r.Mode != report.ModeRun {
		title += " (" + r.Mode + ")"
	}
	text := fmt.Sprintf("%d new finding(s)", r.Total())
	open := r.CurrentOpenCounts()
	openTotal := sumCounts(open)
	if openTotal > 0 {
		text += fmt.Sprintf(", %d open", openTotal)
	}
	facts := []fact{
		{Title: "New", Value: fmt.Sprintf("%d (%s)", r.Total(), countLine(r.Counts))},
		{Title: "Open", Value: fmt.Sprintf("%d (%s)", openTotal, countLine(open))},
		{Title: "Window", Value: r.Since.Format("2 Jan 15:04") + " → " + r.Until.Format("2 Jan 15:04 MST")},
	}
	if failed := r.FailedSources(); len(failed) > 0 {
		facts = append(facts, fact{Title: "Failed sources", Value: strings.Join(failed, ", ")})
	}
	color := ""
	if hasP1(r.Counts) {
		color = colorAttention
	}
	m := newCard(title, text, color)
	m.addFacts(facts)
	if dashboard != "" {
		m.card().Actions = []cardAction{{Type: actionTypeOpenURL, Title: "Open the dashboard", URL: dashboard}}
	}
	return m
}

// buildP1Card renders one P1 finding as an Adaptive Card: CVE, product,
// version, severity, CVSS, KEV/EPSS, fix and action as facts, with an
// Action.OpenUrl button to it.Link (when there is one).
func buildP1Card(it p1Item) message {
	severity := it.Severity
	if severity == "" {
		severity = "unknown"
	}
	cvss := "not rated"
	if it.CVSS > 0 {
		cvss = fmt.Sprintf("%.1f", it.CVSS)
	}
	exploit := "no known exploitation"
	switch {
	case it.KEV && it.EPSS > 0:
		exploit = fmt.Sprintf("exploited in the wild (CISA KEV) · EPSS %.1f%%", it.EPSS*100)
	case it.KEV:
		exploit = "exploited in the wild (CISA KEV)"
	case it.EPSS > 0:
		exploit = fmt.Sprintf("EPSS %.1f%%", it.EPSS*100)
	}
	fixed := "no fix released yet"
	if len(it.Fixed) > 0 {
		fixed = strings.Join(it.Fixed, ", ")
	}
	m := newCard("P1 · "+it.Product+" · "+it.ID, "", colorAttention)
	m.addFacts([]fact{
		{Title: "CVE", Value: it.ID},
		{Title: "Product", Value: it.Product},
		{Title: "Version", Value: it.Constraint},
		{Title: "Severity", Value: severity},
		{Title: "CVSS", Value: cvss},
		{Title: "KEV/EPSS", Value: exploit},
		{Title: "Fixed in", Value: fixed},
		{Title: "Action", Value: it.Action},
	})
	if it.Link != "" {
		m.card().Actions = []cardAction{{Type: actionTypeOpenURL, Title: "View advisory", URL: it.Link}}
	}
	return m
}
