package slack

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/triage"
)

func TestRenderRoutesTenants(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", dashboardTmpl)

	c, _ := match.ParseConstraint("26.7.0")
	kc := func(sc config.Scope) catalog.Product {
		return catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high", Scope: sc}
	}
	local := kc(config.Scope{Tenant: "vasops", Environment: "prod"})
	acme := kc(config.Scope{Tenant: "acme", Environment: "prod", Remote: true, Slack: config.SlackRoute{Channel: "C-ACME"}})
	globex := kc(config.Scope{Tenant: "globex", Environment: "prod", Remote: true})
	entry := func(id, prio string, p catalog.Product) report.Entry {
		return report.Entry{Finding: finding.Finding{ID: id, Product: p.Key(), Title: id, Severity: "high", Match: "affected"}, Product: p,
			Triage: triage.Result{Relevant: "yes", Priority: prio, Method: triage.MethodRules}}
	}
	now := time.Date(2026, 11, 6, 6, 0, 0, 0, time.UTC)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now,
		Products: []catalog.Product{local, acme, globex}, Warnings: []string{"nvd/keycloak: timeout"}, TriageFailures: 2},
		[]report.Entry{entry("CVE-L", "P3", local), entry("CVE-A", "P1", acme), entry("CVE-G", "P2", globex)})
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, m := range *msgs {
		got = append(got, m.Channel)
	}
	// Default channel: the local stack and globex (no channel of its own),
	// with the run's warnings. acme: its own summary and P1 alert.
	if strings.Join(got, " ") != "CDIGEST C-ACME C-ACME" {
		t.Fatalf("channels: %v", got)
	}
	def, acmeSum, acmeAlert := blockText((*msgs)[0].Blocks), blockText((*msgs)[1].Blocks), blockText((*msgs)[2].Blocks)
	if !strings.Contains(def, "CVE-L") || !strings.Contains(def, "globex/prod keycloak") || strings.Contains(def, "CVE-A") ||
		!strings.Contains(def, ":warning: incomplete: source nvd failed (1 warning, see the job log)") {
		t.Errorf("default summary:\n%s", def)
	}
	// Every channel learns its priorities may be rule-based (#41).
	for _, sum := range []string{def, acmeSum} {
		if !strings.Contains(sum, ":warning: Claude triage failed 2 times; priorities are rule-based") {
			t.Errorf("triage failures missing:\n%s", sum)
		}
	}
	// A tenant channel learns the run was incomplete, by source name only (#28).
	if !strings.Contains(acmeSum, "vulnwatch report · acme/prod") || !strings.Contains(acmeSum, "CVE-A") || strings.Contains(acmeSum, "CVE-G") ||
		!strings.Contains(acmeSum, ":warning: incomplete: source nvd failed") || strings.Contains(acmeSum, "timeout") ||
		strings.Contains(acmeSum, "job log") || !strings.Contains(acmeSum, "var-tenant=acme") {
		t.Errorf("acme summary:\n%s", acmeSum)
	}
	if !strings.Contains(acmeAlert, "P1 · acme/prod keycloak") {
		t.Errorf("acme alert:\n%s", acmeAlert)
	}
}

// The same finding in five tenant environments is one summary entry (#23),
// even when one of them has another action.
func TestSummaryGroupsScopesOfOneFinding(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")

	c, _ := match.ParseConstraint("26.7.0")
	var ps []catalog.Product
	var es []report.Entry
	for _, sc := range [][2]string{{"acme", "prod"}, {"acme", "stage"}, {"globex", "prod"}, {"globex", "stage"}, {"initech", "prod"}} {
		p := catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high",
			Scope: config.Scope{Tenant: sc[0], Environment: sc[1], Remote: true}}
		ps = append(ps, p)
		es = append(es, report.Entry{Finding: finding.Finding{ID: "CVE-2026-7", Product: p.Key(), Title: "x", Severity: "high", Match: "affected"}, Product: p,
			Triage: triage.Result{Relevant: "yes", Priority: "P2", Method: triage.MethodRules, Action: "Upgrade to 26.7.1."}})
	}
	es[4].Triage.Action = "Upgrade initech first."
	now := time.Date(2026, 11, 6, 6, 0, 0, 0, time.UTC)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now, Products: ps}, es)
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	sum := blockText((*msgs)[0].Blocks)
	if n := strings.Count(sum, "CVE-2026-7"); n != 1 {
		t.Fatalf("want 1 entry for CVE-2026-7, got %d:\n%s", n, sum)
	}
	for _, want := range []string{
		":large_orange_circle: *keycloak* · *CVE-2026-7*\nx\n      ↳ Upgrade to 26.7.1.\n",
		"      • acme: prod, stage; globex: prod, stage; initech: prod · `26.7.0`",
		"*New:* 1 in 5 environments   :large_orange_circle: 1",
	} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q\n%s", want, sum)
		}
	}
	if strings.Contains(sum, "initech first") {
		t.Errorf("scope-specific action shown:\n%s", sum)
	}
}

func TestRenderCancelled(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := newOutput(t, srv.URL, "CALERT", "").Render(ctx, report.Report{})
	if !errors.Is(err, context.Canceled) || strings.Count(err.Error(), "canceled") != 1 || len(*msgs) != 0 {
		t.Fatalf("%v, %d posts", err, len(*msgs))
	}
}

// One failing channel must not starve the other routes, and a failed
// summary must not skip the route's P1 cards (#22).
func TestRenderFailingRouteDoesNotStopOthers(t *testing.T) {
	srv, msgs := fakeSlack(t, false, "C-ACME", "C-GONE")
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")

	c, _ := match.ParseConstraint("26.7.0")
	kc := func(sc config.Scope) catalog.Product {
		return catalog.Product{Name: "keycloak", Constraint: c, Exposure: "internet", Criticality: "high", Scope: sc}
	}
	acme := kc(config.Scope{Tenant: "acme", Environment: "prod", Remote: true, Slack: config.SlackRoute{Channel: "C-ACME"}})
	beta := kc(config.Scope{Tenant: "beta", Environment: "prod", Remote: true, Slack: config.SlackRoute{Channel: "C-BETA"}})
	gamma := kc(config.Scope{Tenant: "gamma", Environment: "prod", Remote: true, Slack: config.SlackRoute{Channel: "C-GONE", AlertChannel: "C-GAMMA-ALERTS"}})
	entry := func(id string, p catalog.Product) report.Entry {
		return report.Entry{Finding: finding.Finding{ID: id, Product: p.Key(), Title: id, Severity: "high", Match: "affected"}, Product: p,
			Triage: triage.Result{Relevant: "yes", Priority: "P1", Method: triage.MethodRules}}
	}
	now := time.Date(2026, 11, 6, 6, 0, 0, 0, time.UTC)
	rep := report.Build(report.Meta{Mode: report.ModeRun, GeneratedAt: now, Since: now.Add(-24 * time.Hour), Until: now,
		Products: []catalog.Product{acme, beta, gamma}},
		[]report.Entry{entry("CVE-A", acme), entry("CVE-B", beta), entry("CVE-G", gamma)})
	err := o.Render(context.Background(), rep)
	if err == nil || strings.Count(err.Error(), "channel_not_found") != 3 {
		t.Fatalf("want the three failures joined, got %v", err)
	}

	var got []string
	for _, m := range *msgs {
		s := m.Channel
		if m.Failed {
			s += "(failed)"
		}
		got = append(got, s)
	}
	// acme fails (summary and card), beta after it still gets everything,
	// gamma's card goes out although its summary channel is gone.
	want := "CDIGEST C-ACME(failed) C-ACME(failed) C-BETA C-BETA C-GONE(failed) C-GAMMA-ALERTS"
	if strings.Join(got, " ") != want {
		t.Fatalf("posts: %v, want %s", got, want)
	}
}
