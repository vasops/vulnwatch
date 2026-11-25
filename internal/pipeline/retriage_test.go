package pipeline

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/internal/triage"
)

// A stored Claude verdict is weighed again when the product's exposure or
// criticality changed since: the more urgent of it and the rules wins.
func TestOpenItemReweighsStoredVerdicts(t *testing.T) {
	c, err := match.ParseConstraint("26.1.0")
	if err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{ID: "CVE-1", CVSS: 9.8, Affected: []finding.Range{{Introduced: "26.0.0", Fixed: "26.1.4"}}, Fixed: []string{"26.1.4"}}
	tests := []struct {
		name               string
		method, prio       string
		decidedExposure    string // empty: a row written before exposure was stored
		decidedCriticality string
		exposure           string
		criticality        string
		want               string
	}{
		{"same settings", triage.MethodLLM, "P3", "internal", "medium", "internal", "medium", "P3"},
		{"now internet-facing", triage.MethodLLM, "P3", "internal", "medium", "internet", "medium", "P1"},
		{"now high criticality", triage.MethodLLM, "P3", "internal", "medium", "internal", "high", "P2"},
		{"less exposed: Claude's P1 stays", triage.MethodLLM, "P1", "internet", "medium", "internal", "medium", "P1"},
		{"legacy row without settings", triage.MethodLLM, "P3", "", "", "internet", "medium", "P3"},
		{"rules follow the settings", triage.MethodRules, "P2", "internal", "medium", "internet", "medium", "P1"},
		{"legacy fallback row: rules", triage.MethodFallback, "P4", "", "", "internal", "medium", "P2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := state.NewDetail(f, tt.prio, "yes", tt.method, "26.1.0")
			d.Exposure, d.Criticality = tt.decidedExposure, tt.decidedCriticality
			p := catalog.Product{Name: "keycloak", Constraint: c, Exposure: tt.exposure, Criticality: tt.criticality}
			it, st := openItem(p, f.ID, d, time.Time{}, false)
			if st != openListed || it.Priority != tt.want {
				t.Fatalf("got %s (%d), want %s", it.Priority, st, tt.want)
			}
		})
	}
}

// failingCompleter is Claude being unavailable.
type failingCompleter struct{ calls int }

func (c *failingCompleter) Complete(context.Context, string, string, map[string]any) (string, error) {
	c.calls++
	return "", errors.New("overloaded")
}

// partialCompleter fails the prompts that mention fail and answers the rest.
type partialCompleter struct {
	keyCompleter
	fail string
}

func (c *partialCompleter) Complete(ctx context.Context, sys, user string, schema map[string]any) (string, error) {
	if strings.Contains(user, c.fail) {
		return "", errors.New("overloaded")
	}
	return c.keyCompleter.Complete(ctx, sys, user, schema)
}

func detailOf(t *testing.T, e *env, product, id string) *state.Detail {
	t.Helper()
	p, err := e.store.Lookup(context.Background(), product, []string{id})
	if err != nil || p == nil || p.Detail == nil {
		t.Fatalf("lookup %s/%s: %v %+v", product, id, err, p)
	}
	return p.Detail
}

// A finding Claude gave no verdict for is asked again in a later run with
// budget left, without being reported again; history verdicts by the rules
// and legacy fallback rows are never asked again.
func TestUntriagedFindingsAreRetried(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		maxFindings int
		newFinding  bool // a new finding in the second run takes the budget
		wantRetry   bool
	}{
		{"budget left", true, 10, false, true},
		{"budget used by new findings", true, 1, true, false},
		{"LLM triage off", false, 10, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := setup(t)
			cfg := e.cfg.Triage
			cfg.Enabled = true
			if _, err := e.run(t, func(o *Options) {
				o.Triager = triage.New(cfg, &failingCompleter{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			}); err == nil || !strings.Contains(err.Error(), "every Claude call failed") {
				t.Fatalf("Claude answered nothing: the run fails: %v", err)
			}
			if d := detailOf(t, e, "keycloak", "CVE-2026-1"); !d.Untriaged || d.Method != triage.MethodFallback || d.Exposure != "internet" {
				t.Fatalf("a fallback is stored as owed: %+v", d)
			}

			e.now = e.now.Add(24 * time.Hour)
			if tt.newFinding {
				src := e.src[0].(*fakeSource)
				src.fs = append(src.fs, finding.Finding{ID: "GHSA-kc-2", Product: "keycloak", Title: "new", CVSS: 7.0, Sources: []string{"ghsa"}, Modified: e.now})
			}
			c := &keyCompleter{}
			cfg.Enabled, cfg.MaxFindings = tt.enabled, tt.maxFindings
			rep, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil))) })
			if err != nil {
				t.Fatal(err)
			}
			retried := strings.Contains(strings.Join(c.ids, " "), "CVE-2026-1")
			if retried != tt.wantRetry {
				t.Fatalf("retried=%v, asked for %v", retried, c.ids)
			}
			if tt.newFinding != (rep.Total() == 1) || rep.Unchanged != 2 {
				t.Fatalf("a retried finding is not reported again: total=%d unchanged=%d", rep.Total(), rep.Unchanged)
			}
			d := detailOf(t, e, "keycloak", "CVE-2026-1")
			if !tt.wantRetry {
				if !d.Untriaged {
					t.Fatalf("still owed: %+v", d)
				}
				return
			}
			if d.Untriaged || d.Method != triage.MethodLLM || d.Summary != "s" {
				t.Fatalf("Claude's verdict is stored: %+v", d)
			}
			if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2026-1" || rep.Open[0].Summary != "s" {
				t.Fatalf("listed as still open with Claude's verdict: %+v", rep.Open)
			}

			// Once triaged, it is not asked again.
			e.now = e.now.Add(24 * time.Hour)
			c.ids = nil
			if _, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil))) }); err != nil || len(c.ids) != 0 {
				t.Fatalf("asked again: %v %v", err, c.ids)
			}
		})
	}
}

// Failed Claude calls are counted, the retry of owed verdicts included. A
// run Claude answered nothing in fails after reporting and writing the
// state; a run with some verdicts does not.
func TestTriageFailures(t *testing.T) {
	e := setup(t)
	cfg := e.cfg.Triage
	cfg.Enabled = true
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rep, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, &failingCompleter{}, log) })
	if err == nil || rep == nil || rep.TriageFailures != 1 || len(e.out.reports) != 1 {
		t.Fatalf("a dead key fails the run after reporting: %v %+v", err, rep)
	}
	if d := detailOf(t, e, "keycloak", "CVE-2026-1"); !d.Untriaged {
		t.Fatalf("the state is written: %+v", d)
	}

	// The new finding is answered, the retry of the owed one fails.
	e.now = e.now.Add(24 * time.Hour)
	src := e.src[0].(*fakeSource)
	src.fs = append(src.fs, finding.Finding{ID: "GHSA-kc-2", Product: "keycloak", Title: "new", CVSS: 7.0, Sources: []string{"ghsa"}, Modified: e.now})
	c := &partialCompleter{fail: "CVE-2026-1"}
	rep, err = e.run(t, func(o *Options) { o.Triager = triage.New(cfg, c, log) })
	if err != nil || rep.TriageFailures != 1 || rep.Total() != 1 || !strings.Contains(strings.Join(c.ids, " "), "GHSA-kc-2") {
		t.Fatalf("a failed retry is counted, the run succeeds: %v failures=%d", err, rep.TriageFailures)
	}

	// After an API error the owed verdict is not asked for (#44).
	e.now = e.now.Add(24 * time.Hour)
	src.fs = append(src.fs, finding.Finding{ID: "GHSA-kc-3", Product: "keycloak", Title: "newer", CVSS: 7.0, Sources: []string{"ghsa"}, Modified: e.now})
	fc := &failingCompleter{}
	rep, err = e.run(t, func(o *Options) { o.Triager = triage.New(cfg, fc, log) })
	if err == nil || fc.calls != 1 || rep.TriageFailures != 1 || !detailOf(t, e, "keycloak", "CVE-2026-1").Untriaged {
		t.Fatalf("only the new finding is sent: calls=%d failures=%d %v", fc.calls, rep.TriageFailures, err)
	}
}

// usageCompleter answers like keyCompleter and reports 10 input and 5
// output tokens per request.
type usageCompleter struct {
	keyCompleter
	calls int64
}

func (c *usageCompleter) Complete(ctx context.Context, sys, user string, schema map[string]any) (string, error) {
	c.calls++
	return c.keyCompleter.Complete(ctx, sys, user, schema)
}

func (c *usageCompleter) Usage() triage.Usage {
	return triage.Usage{Requests: c.calls, InputTokens: 10 * c.calls, OutputTokens: 5 * c.calls, CacheCreationInputTokens: 2 * c.calls}
}

// The usage covers both triage passes of a run: the new findings and the
// owed retry. A run without triage reports none.
func TestTriageUsage(t *testing.T) {
	e := setup(t)
	cfg := e.cfg.Triage
	cfg.Enabled, cfg.Model = true, "claude-test"
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if rep, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, &failingCompleter{}, log) }); err == nil || rep.TriageUsage != nil {
		t.Fatalf("a completer without usage reports none: %v %+v", err, rep.TriageUsage)
	}

	e.now = e.now.Add(24 * time.Hour)
	src := e.src[0].(*fakeSource)
	src.fs = append(src.fs, finding.Finding{ID: "GHSA-kc-2", Product: "keycloak", Title: "new", CVSS: 7.0, Sources: []string{"ghsa"}, Modified: e.now})
	c := &usageCompleter{}
	rep, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, c, log) })
	if err != nil {
		t.Fatal(err)
	}
	if c.calls != 2 {
		t.Fatalf("one request for the new finding, one for the owed retry: %d", c.calls)
	}
	want := &report.TriageUsage{Model: "claude-test", Requests: 2, InputTokens: 20, OutputTokens: 10, CacheCreationInputTokens: 4}
	if rep.TriageUsage == nil || *rep.TriageUsage != *want {
		t.Fatalf("usage = %+v, want %+v", rep.TriageUsage, want)
	}

	e.now = e.now.Add(24 * time.Hour)
	if rep, err = e.run(t, func(o *Options) { o.Triager = nil }); err != nil || rep.TriageUsage != nil {
		t.Fatalf("a run without triage has no usage: %v %+v", err, rep.TriageUsage)
	}
}

func TestRuleVerdictsAreNotRetried(t *testing.T) {
	e := history(t)
	if _, err := e.run(t, stackWith(t, e, "26.1.0")); err != nil {
		t.Fatal(err)
	}
	d := detailOf(t, e, "keycloak", "CVE-2025-2")
	if d.Method != triage.MethodRules || d.Untriaged {
		t.Fatalf("history is rule-based by design: %+v", d)
	}
	// A row written before rules and fallbacks were told apart.
	ctx := context.Background()
	prior, err := e.store.Lookup(ctx, "keycloak", []string{"CVE-2025-2"})
	if err != nil {
		t.Fatal(err)
	}
	legacy := *prior.Detail
	legacy.Method, legacy.Exposure, legacy.Criticality = triage.MethodFallback, "", ""
	if err := e.store.Commit(ctx, e.now, []state.Record{{Product: "keycloak", ID: prior.ID, IDs: []string{prior.ID}, PriorID: prior.ID, Snapshot: prior.Snapshot, Detail: legacy}}, nil, false); err != nil {
		t.Fatal(err)
	}

	e.now = e.now.Add(24 * time.Hour)
	c := &keyCompleter{}
	rep, err := e.run(t, func(o *Options) {
		stackWith(t, e, "26.1.0")(o)
		cfg := e.cfg.Triage
		cfg.Enabled = true
		o.Triager = triage.New(cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	})
	if err != nil || len(c.ids) != 0 {
		t.Fatalf("rule verdicts are not sent to Claude: %v %v", err, c.ids)
	}
	if len(rep.Open) != 1 || rep.Open[0].ID != "CVE-2025-2" || rep.Open[0].Priority != "P2" {
		t.Fatalf("the legacy row is listed by the rules: %+v", rep.Open)
	}
}
