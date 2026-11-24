package teams

import (
	"fmt"
	"slices"
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

// adaptiveCard targets schema 1.5: Teams renders 1.6 and older.
type adaptiveCard struct {
	Schema  string         `json:"$schema"`
	Type    string         `json:"type"`
	Version string         `json:"version"`
	Body    []cardElement  `json:"body,omitempty"`
	Actions []cardAction   `json:"actions,omitempty"`
	MSTeams *msTeamsConfig `json:"msteams,omitempty"`
}

// cardElement is a TextBlock or a FactSet, in one struct with omitempty
// fields rather than an interface per type.
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

// cardAction is an Action.OpenUrl button; a webhook does not render
// Action.Submit.
type cardAction struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// msTeamsConfig: width full stops Teams rendering the card in a narrow column.
type msTeamsConfig struct {
	Width string `json:"width,omitempty"`
}

// colorAttention colours the heading of a P1: the format has no card-level
// accent colour.
const colorAttention = "Attention"

const (
	messageType       = "message"
	cardContentType   = "application/vnd.microsoft.card.adaptive"
	cardSchema        = "http://adaptivecards.io/schemas/adaptive-card.json"
	cardType          = "AdaptiveCard"
	cardVersion       = "1.5"
	actionTypeOpenURL = "Action.OpenUrl"
)

// newCard wraps a card with a heading in the message envelope.
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

func (m *message) card() *adaptiveCard { return &m.Attachments[0].Content }

func (m *message) addFacts(facts []fact) {
	c := m.card()
	c.Body = append(c.Body, cardElement{Type: "FactSet", Facts: facts})
}

// p1Item is one P1 finding as shown on a card.
type p1Item struct {
	ID            string
	Product       string
	Constraint    string
	Severity      string
	CVSS          float64
	KEV           bool
	PublicExploit bool
	EPSS          float64
	Fixed         []string
	Action        string
	Link          string
	// Scopes is the number of environments the finding is P1 in. With one or
	// none the card shows Constraint as a Version fact, else the Lines.
	Scopes int
	Lines  []report.Line
	// ScopeNames is for the audit log.
	ScopeNames string
}

// dashboardLink fills {from} and {to} of a Grafana URL template with now-30d
// and now. Empty tmpl: no link.
func dashboardLink(tmpl string) string {
	if tmpl == "" {
		return ""
	}
	return strings.NewReplacer("{from}", "now-30d", "{to}", "now").Replace(tmpl)
}

// targetURL is where a P1 alert goes: alert if set, else the main URL.
func targetURL(main, alert string) string {
	if alert != "" {
		return alert
	}
	return main
}

// advisoryLink is the first advisory page URL, else the first non-empty of
// links: the card has a single button.
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

// openItemLink is advisoryLink for an OpenItem, whose extra reference is Link.
func openItemLink(it report.OpenItem) string {
	return advisoryLink(it.Advisories, []string{it.Link})
}

// historyAction is the action of a full-history P1: Claude's if triaged,
// else a generic one from the fixed versions.
func historyAction(it report.OpenItem) string {
	switch {
	case it.Action != "":
		return it.Action
	case len(it.Fixed) > 0:
		return "Upgrade to a fixed version: " + strings.Join(it.Fixed, ", ") + "."
	}
	return "No fix released yet: check the advisory for mitigations."
}

// maxAffectedLines caps the affected facts; the rest become one fact.
const maxAffectedLines = 20

// p1Items collects one item per P1 finding: new or updated ones, then those
// first seen by a full-history check. The two kinds are grouped separately.
func p1Items(r report.Report) []p1Item {
	var out []p1Item
	var items []report.Item
	for _, it := range r.Items() {
		if it.Priority == "P1" {
			items = append(items, it)
		}
	}
	for _, f := range report.Findings(items) {
		it := f.Representative
		out = append(out, p1Item{
			ID: f.ID, Product: productName(f.Scopes, it.Scope, it.Product), Constraint: it.Constraint,
			Severity: it.Severity, CVSS: it.CVSS, KEV: it.KEV, PublicExploit: it.PublicExploit, EPSS: it.EPSS, Fixed: it.Fixed,
			Action: f.Action, Link: advisoryLink(it.Advisories, it.Links),
			Scopes: len(f.Scopes), Lines: f.Lines, ScopeNames: report.ScopeList(f.Scopes),
		})
	}
	var open []report.OpenItem
	for _, it := range r.Open {
		if it.Priority == "P1" && it.FirstSeen {
			open = append(open, it)
		}
	}
	for _, f := range report.OpenFindings(open, historyAction) {
		it := f.Representative
		out = append(out, p1Item{
			ID: f.ID, Product: productName(f.Scopes, it.Scope, it.Product), Constraint: it.Constraint,
			Severity: it.Severity, CVSS: it.CVSS, KEV: it.KEV, PublicExploit: it.PublicExploit, EPSS: it.EPSS, Fixed: it.Fixed,
			Action: f.Action, Link: openItemLink(it),
			Scopes: len(f.Scopes), Lines: f.Lines, ScopeNames: report.ScopeList(f.Scopes),
		})
	}
	return out
}

// productName is bare for several environments, which the card lists under
// Affected, else scoped.
func productName(scopes []report.ScopeRef, scope, product string) string {
	if len(scopes) > 1 {
		return product
	}
	return report.Named(scope, product)
}

// versions shows a union constraint ("26.7.0 || 20.0.3") as a list.
func versions(constraint string) string {
	return strings.ReplaceAll(constraint, " || ", ", ")
}

// countLine renders "P1: 1, P2: 57", skipping zeros; "none" when all are zero.
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

// buildSummaryCard renders the run summary: counts, dashboard link and failed
// sources.
func buildSummaryCard(r report.Report, dashboard string) message {
	title := "vulnwatch report · " + r.Until.Format("2 Jan 2006")
	if r.Mode != report.ModeRun {
		title += " (" + r.Mode + ")"
	}
	// Open stays per scope so it keeps matching findings_open.
	found := report.Count(report.Findings(r.Items()))
	inEnvs := ""
	if found.Scopes > found.Findings {
		inEnvs = fmt.Sprintf(" in %d environments", found.Scopes)
	}
	text := fmt.Sprintf("%d new finding(s)%s", found.Findings, inEnvs)
	open := r.CurrentOpenCounts()
	openTotal := sumCounts(open)
	if openTotal > 0 {
		text += fmt.Sprintf(", %d open", openTotal)
	}
	facts := []fact{
		{Title: "New", Value: fmt.Sprintf("%d%s (%s)", found.Findings, inEnvs, countLine(found.ByPriority))},
		{Title: "Open", Value: fmt.Sprintf("%d (%s)", openTotal, countLine(open))},
		{Title: "Window", Value: r.Since.Format("2 Jan 15:04") + " → " + r.Until.Format("2 Jan 15:04 MST")},
	}
	if failed := r.FailedSources(); len(failed) > 0 {
		facts = append(facts, fact{Title: "Failed sources", Value: strings.Join(failed, ", ")})
	}
	color := ""
	if hasP1(found.ByPriority) {
		color = colorAttention
	}
	m := newCard(title, text, color)
	m.addFacts(facts)
	if dashboard != "" {
		m.card().Actions = []cardAction{{Type: actionTypeOpenURL, Title: "Open the dashboard", URL: dashboard}}
	}
	return m
}

// buildP1Card renders one P1 finding; the button is left out without a link.
func buildP1Card(it p1Item) message {
	severity := it.Severity
	if severity == "" {
		severity = "unknown"
	}
	cvss := "not rated"
	if it.CVSS > 0 {
		cvss = fmt.Sprintf("%.1f", it.CVSS)
	}
	var signals []string
	if it.KEV {
		signals = append(signals, "exploited in the wild (CISA KEV)")
	}
	if it.PublicExploit {
		signals = append(signals, "public exploit")
	}
	if it.EPSS > 0 {
		signals = append(signals, fmt.Sprintf("EPSS %.1f%%", it.EPSS*100))
	}
	exploit := "no known exploitation"
	if len(signals) > 0 {
		exploit = strings.Join(signals, " · ")
	}
	fixed := "no fix released yet"
	if len(it.Fixed) > 0 {
		fixed = strings.Join(it.Fixed, ", ")
	}
	heading := "P1 · " + it.Product + " · " + it.ID
	several := it.Scopes > 1
	if several {
		heading += fmt.Sprintf(" · %d environments", it.Scopes)
	}
	facts := []fact{
		{Title: "CVE", Value: it.ID},
		{Title: "Product", Value: it.Product},
	}
	if !several {
		facts = append(facts, fact{Title: "Version", Value: it.Constraint})
	}
	facts = append(facts,
		fact{Title: "Severity", Value: severity},
		fact{Title: "CVSS", Value: cvss},
		fact{Title: "KEV/EPSS", Value: exploit},
		fact{Title: "Fixed in", Value: fixed},
		fact{Title: "Action", Value: it.Action},
	)
	m := newCard(heading, "", colorAttention)
	m.addFacts(facts)
	if several {
		m.card().Body = append(m.card().Body, cardElement{Type: "TextBlock", Text: "Affected", Weight: "Bolder", Wrap: true})
		m.addFacts(affectedFacts(it.Lines))
	}
	if it.Link != "" {
		m.card().Actions = []cardAction{{Type: actionTypeOpenURL, Title: "View advisory", URL: it.Link}}
	}
	return m
}

// affectedFacts is one fact per affected line (versions: environments); the
// lines past the cap are counted in one last fact.
func affectedFacts(lines []report.Line) []fact {
	var out []fact
	for i, l := range lines {
		if i == maxAffectedLines {
			var rest []report.ScopeRef
			for _, l := range lines[i:] {
				for _, s := range l.Scopes {
					if !slices.Contains(rest, s) {
						rest = append(rest, s)
					}
				}
			}
			noun := "environments"
			if len(rest) == 1 {
				noun = "environment"
			}
			out = append(out, fact{Title: fmt.Sprintf("+%d more %s", len(rest), noun), Value: ""})
			break
		}
		out = append(out, fact{Title: versions(l.Constraint), Value: l.Names()})
	}
	return out
}
