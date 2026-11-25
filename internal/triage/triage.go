// Package triage prioritizes findings with Claude, validating the structured
// output strictly and falling back to deterministic rules on any failure.
package triage

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/match"
)

// Allowed enum values.
var (
	Relevances = []string{"yes", "no", "uncertain"}
	Priorities = []string{"P1", "P2", "P3", "P4"}
)

// How a result was produced.
const (
	MethodLLM      = "llm"      // triaged by Claude
	MethodRules    = "rules"    // deterministic by design (not affected)
	MethodFallback = "fallback" // Claude unavailable/invalid or cost guard: "not triaged"
)

// Item is one finding with its product context.
type Item struct {
	Finding finding.Finding
	Product catalog.Product
}

// Key identifies an item within a batch; the same CVE can hit two products.
// It holds the tenant and environment, so the prompt uses opaque keys.
func (it Item) Key() string { return it.Product.Key() + "/" + it.Finding.ID }

// Result is the triage outcome for one item.
type Result struct {
	Relevant  string `json:"relevant"`
	Priority  string `json:"priority"`
	Summary   string `json:"summary"`
	Reasoning string `json:"reasoning"`
	Action    string `json:"action"`
	Method    string `json:"method"`
	Note      string `json:"note,omitempty"`
}

// Triaged reports whether a human-grade triage (LLM or rules) was applied.
func (r Result) Triaged() bool { return r.Method != MethodFallback }

// Completer sends one prompt and returns the model's text output.
type Completer interface {
	Complete(ctx context.Context, system, user string, schema map[string]any) (string, error)
}

// Usage is what Claude requests used: the requests that got a response and
// their tokens.
type Usage struct {
	Requests                 int64
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
}

// Add sums two usages.
func (u Usage) Add(o Usage) Usage {
	return Usage{
		Requests:                 u.Requests + o.Requests,
		InputTokens:              u.InputTokens + o.InputTokens,
		OutputTokens:             u.OutputTokens + o.OutputTokens,
		CacheCreationInputTokens: u.CacheCreationInputTokens + o.CacheCreationInputTokens,
		CacheReadInputTokens:     u.CacheReadInputTokens + o.CacheReadInputTokens,
	}
}

// UsageReporter is implemented by a Completer that knows what it used.
type UsageReporter interface {
	Usage() Usage
}

// Triager runs batched triage.
type Triager struct {
	cfg config.Triage
	c   Completer // nil disables LLM triage (fallback for everything)
	log *slog.Logger
}

func New(cfg config.Triage, c Completer, log *slog.Logger) *Triager {
	return &Triager{cfg: cfg, c: c, log: log}
}

// Budget is how many findings one Triage call sends to Claude at most:
// max_findings, or 0 with LLM triage off.
func (t *Triager) Budget() int {
	if t.c == nil || !t.cfg.Enabled {
		return 0
	}
	return max(t.cfg.MaxFindings, 0)
}

// WithBudget returns a Triager that sends at most n findings to Claude.
func (t *Triager) WithBudget(n int) *Triager {
	c := *t
	c.cfg.MaxFindings = max(min(n, t.cfg.MaxFindings), 0)
	return &c
}

// Usage returns the model and the total usage of the completer, shared by
// every WithBudget copy; ok is false when there is no completer or it does
// not report usage.
func (t *Triager) Usage() (model string, u Usage, ok bool) {
	r, isReporter := t.c.(UsageReporter)
	if !isReporter {
		return "", Usage{}, false
	}
	return t.cfg.Model, r.Usage(), true
}

// Stats counts the batches Triage sent to Claude.
type Stats struct {
	Batches  int // sent to Claude
	Failed   int // left findings without a verdict: API error, or invalid output after the retry
	Answered int // got at least one valid verdict (a partly invalid batch is also failed)
	// APIError: an API call failed, so the batches after it were not sent
	// (not counted in Batches or Failed); their findings get the rules.
	APIError bool
}

// Add sums the stats of two Triage calls.
func (s Stats) Add(o Stats) Stats {
	return Stats{s.Batches + o.Batches, s.Failed + o.Failed, s.Answered + o.Answered, s.APIError || o.APIError}
}

// Dead reports that Claude was asked and answered nothing: a bad API key or
// model name, or the API down.
func (s Stats) Dead() bool { return s.Batches > 0 && s.Answered == 0 }

// errAPI marks a failed API call, as opposed to invalid output.
var errAPI = errors.New("API call failed")

// Triage returns one result per item, keyed by Item.Key. It never fails:
// LLM errors degrade to deterministic results marked as not triaged, and
// are counted in Stats. After an API error (the client has retried it
// already) no further batch is sent, so a hung API can't eat the run's
// deadline batch by batch.
func (t *Triager) Triage(ctx context.Context, items []Item) (map[string]Result, Stats) {
	out := make(map[string]Result, len(items))
	var candidates []Item
	for _, it := range items {
		if it.Finding.Match == string(match.NotAffected) {
			out[it.Key()] = notAffected(it)
			continue
		}
		candidates = append(candidates, it)
	}
	// Spend the cost guard on the most severe items first.
	slices.SortStableFunc(candidates, func(a, b Item) int {
		pa, pb := Deterministic(a).Priority, Deterministic(b).Priority
		return cmp.Or(cmp.Compare(pa, pb), cmp.Compare(effectiveScore(b.Finding), effectiveScore(a.Finding)))
	})
	limit := len(candidates)
	if t.c == nil || !t.cfg.Enabled {
		limit = 0
	} else if t.cfg.MaxFindings < limit {
		limit = t.cfg.MaxFindings
	}
	for _, it := range candidates[limit:] {
		r := Deterministic(it)
		if t.c == nil || !t.cfg.Enabled {
			r.Note = "not triaged: LLM triage disabled"
		} else {
			r.Note = fmt.Sprintf("not triaged: cost guard (max %d findings per run)", t.cfg.MaxFindings)
		}
		out[it.Key()] = r
	}
	var st Stats
	llm := candidates[:limit]
	batch := max(t.cfg.BatchSize, 1)
	for start := 0; start < len(llm); start += batch {
		chunk := llm[start:min(start+batch, len(llm))]
		var res map[string]Result
		note := "not triaged: LLM output invalid or unavailable"
		if st.APIError {
			note = "not triaged: the Claude API failed earlier in this run"
		} else {
			var err error
			res, err = t.runBatch(ctx, chunk)
			st.Batches++
			if len(res) > 0 {
				st.Answered++
			}
			if err != nil {
				st.Failed++
				st.APIError = errors.Is(err, errAPI)
				t.log.Warn("LLM triage failed, using deterministic fallback", "batch_size", len(chunk), "triaged", len(res), "err", err)
				if st.APIError && start+batch < len(llm) {
					t.log.Warn("Claude API failed: the remaining findings are not sent", "findings", len(llm)-start-batch)
				}
			}
		}
		for _, it := range chunk {
			if r, ok := res[it.Key()]; ok {
				out[it.Key()] = t.guard(ctx, it, r)
				continue
			}
			r := Deterministic(it)
			r.Note = note
			out[it.Key()] = r
		}
	}
	return out, st
}

// guard keeps Claude's verdict from hiding what the facts say is serious:
// advisory text is public input and may try to talk the model down. An
// exploited finding (KEV, or CISA SSVC exploitation "active" on an important
// product), or an affected one with CVSS 9 or more, stays relevant and at
// least P2. An affected finding the rules rate P1 or P2 stays listed: Claude
// may lower it to P3, but its "not relevant" becomes "uncertain" (#17).
// Every verdict below the rule-based priority is written to the audit log.
func (t *Triager) guard(ctx context.Context, it Item, r Result) Result {
	rule := Deterministic(it)
	f := it.Finding
	serious := exploited(f, it.Product) || (f.Match == string(match.Affected) && effectiveScore(f) >= 9)
	floored := false
	if serious && (r.Relevant == "no" || r.Priority > "P2") {
		floored = true
		if r.Relevant == "no" {
			r.Relevant = "uncertain"
		}
		if r.Priority > "P2" {
			r.Priority = "P2"
		}
		r.Note = strings.TrimPrefix(r.Note+"; ", "; ") + "raised to " + r.Priority + ": exploited (KEV or SSVC active) or critical and affected, Claude's verdict was lower"
	} else if f.Match == string(match.Affected) && rule.Priority <= "P2" && (r.Relevant == "no" || r.Priority > "P3") {
		floored = true
		if r.Relevant == "no" {
			r.Relevant = "uncertain"
		}
		r.Priority = min(r.Priority, "P3")
		r.Note = strings.TrimPrefix(r.Note+"; ", "; ") + "kept at " + r.Priority + ": our version is affected and the rules say " + rule.Priority + ", Claude rated it not relevant or P4"
	}
	if floored || r.Priority > rule.Priority || (r.Relevant == "no" && rule.Relevant != "no") {
		logx.Audit(ctx, t.log, "triage below the rules", "key", it.Key(), "rule_priority", rule.Priority,
			"llm_priority", r.Priority, "llm_relevant", r.Relevant, "floored", floored, "kev", f.KEV, "cvss", f.CVSS)
	}
	return r
}

// runBatch calls the model and validates; the items without a valid result
// are sent once more. It returns the valid results, and an error when some
// items have none: errAPI when the call itself failed (not retried here,
// the client retries).
func (t *Triager) runBatch(ctx context.Context, items []Item) (map[string]Result, error) {
	sys := systemPrompt(t.cfg.Language)
	got := map[string]Result{}
	items = slices.Clone(items)
	var lastErr error
	for attempt := 1; attempt <= 2 && len(items) > 0; attempt++ {
		if ctx.Err() != nil {
			return got, ctx.Err()
		}
		user, keys, err := buildPrompt(items)
		if err != nil {
			return got, err
		}
		raw, err := t.c.Complete(ctx, sys, user, outputSchema)
		if err != nil {
			return got, fmt.Errorf("%w: %w", errAPI, err)
		}
		res, err := Validate(raw, keys)
		for i, k := range keys {
			if r, ok := res[k]; ok {
				got[items[i].Key()] = r
			}
		}
		if err == nil {
			return got, nil
		}
		lastErr = err
		t.log.Debug("LLM output rejected", "attempt", attempt, "valid", len(res), "err", err)
		items = slices.DeleteFunc(items, func(it Item) bool { _, ok := got[it.Key()]; return ok })
	}
	return got, lastErr
}

type llmOutput struct {
	Results []llmResult `json:"results"`
}

type llmResult struct {
	Key       string `json:"key"`
	Relevant  string `json:"relevant"`
	Priority  string `json:"priority"`
	Summary   string `json:"summary"`
	Reasoning string `json:"reasoning"`
	Action    string `json:"action"`
}

// Validate strictly decodes model output and checks that every expected key
// is present exactly once with allowed enum values and non-empty text fields.
// With an error the map still holds the valid results (none when the output
// can't be decoded); a key given twice has none.
func Validate(raw string, keys []string) (map[string]Result, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var out llmOutput
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON object")
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	res := map[string]Result{}
	seen := map[string]bool{}
	var errs []error
	for i, r := range out.Results {
		switch {
		case !want[r.Key]:
			errs = append(errs, fmt.Errorf("results[%d]: unexpected key %q", i, r.Key))
			continue
		case seen[r.Key]:
			errs = append(errs, fmt.Errorf("results[%d]: duplicate key %q", i, r.Key))
			delete(res, r.Key)
			continue
		}
		seen[r.Key] = true
		n := len(errs)
		if !slices.Contains(Relevances, r.Relevant) {
			errs = append(errs, fmt.Errorf("%s: relevant %q not in %v", r.Key, r.Relevant, Relevances))
		}
		if !slices.Contains(Priorities, r.Priority) {
			errs = append(errs, fmt.Errorf("%s: priority %q not in %v", r.Key, r.Priority, Priorities))
		}
		for name, v := range map[string]string{"summary": r.Summary, "reasoning": r.Reasoning, "action": r.Action} {
			if strings.TrimSpace(v) == "" {
				errs = append(errs, fmt.Errorf("%s: %s is empty", r.Key, name))
			}
		}
		if len(errs) == n {
			res[r.Key] = Result{Relevant: r.Relevant, Priority: r.Priority, Summary: r.Summary, Reasoning: r.Reasoning, Action: r.Action, Method: MethodLLM}
		}
	}
	for _, k := range keys {
		if !seen[k] {
			errs = append(errs, fmt.Errorf("missing result for %q", k))
		}
	}
	return res, errors.Join(errs...)
}

// effectiveScore is the CVSS score, or a stand-in derived from the severity label.
func effectiveScore(f finding.Finding) float64 {
	if f.CVSS > 0 {
		return f.CVSS
	}
	switch f.Severity {
	case finding.SeverityCritical:
		return 9.0
	case finding.SeverityHigh:
		return 7.0
	case finding.SeverityMedium, finding.SeverityUnknown, "":
		return 5.0 // unknown severity is never silently demoted
	case finding.SeverityLow:
		return 2.0
	}
	return 0
}

// EPSSHigh is the EPSS score from which the rules raise a priority: the
// default sources.*.min_epss.
const EPSSHigh = 0.1

// exploited reports KEV-listed findings, and findings CISA's SSVC rates
// exploitation "active" on an important (internet-facing or high-criticality)
// product: SSVC often says so before KEV lists it.
func exploited(f finding.Finding, p catalog.Product) bool {
	important := p.Exposure == "internet" || p.Criticality == "high"
	return f.KEV || (important && f.SSVCExploitation == "active")
}

// Deterministic computes the rule-based priority from CVSS, KEV and SSVC
// exploitation, EPSS, exposure, criticality and the version match. EPSS only
// raises a priority (it lags new CVEs); unless exploited, a finding that may
// not affect our version (match unknown) is at most P2. Used as the fallback
// ("not triaged") result.
func Deterministic(it Item) Result {
	f, p := it.Finding, it.Product
	exposed := p.Exposure == "internet"
	important := exposed || p.Criticality == "high"
	affected := f.Match == string(match.Affected)
	score := effectiveScore(f)
	var prio string
	switch {
	case f.Match == string(match.NotAffected):
		prio = "P4"
	case exploited(f, p) && important:
		prio = "P1"
	case f.KEV:
		prio = "P2"
	case score >= 9 && exposed:
		prio = "P1"
	case score >= 9, score >= 7 && important:
		prio = "P2"
	case score >= 7 && f.Confirmed():
		prio = "P2" // the advisory's vulnerable code is in a running image
	case score >= 4:
		prio = "P3"
	default:
		prio = "P4"
	}
	if f.Match != string(match.NotAffected) {
		if f.EPSS >= EPSSHigh {
			raised := "P2"
			if important && affected {
				raised = "P1"
			}
			prio = min(prio, raised)
		}
		if !exploited(f, p) && !affected {
			prio = max(prio, "P2")
		}
	}
	relevant := "uncertain"
	switch f.Match {
	case string(match.Affected):
		relevant = "yes"
	case string(match.NotAffected):
		relevant = "no"
	}
	action := "Review the advisory; no fixed version is listed yet."
	switch {
	case p.OS != nil && len(f.Fixed) > 0:
		action = fmt.Sprintf("Install the %s %s kernel %s or newer and reboot the nodes still running an affected kernel (%s).", p.OS.Name, p.OS.Release, f.Fixed[0], p.Constraint)
	case f.ImageOnly():
		p := f.Packages[0]
		action = fmt.Sprintf("Deploy an image with %s %s or newer (%s): the product's next release, or ask the vendor for a rebuilt image.", p.Name, cmp.Or(p.Fixed, "(no fix yet)"), p.Image)
	case len(f.Fixed) > 0:
		action = upgradeAction(p.Constraint, f)
	}
	return Result{
		Relevant:  relevant,
		Priority:  prio,
		Summary:   cmp.Or(f.Title, f.ID),
		Reasoning: fmt.Sprintf("Rule-based: CVSS %.1f, KEV %v, SSVC exploitation %s, EPSS %.2f, exposure %s, criticality %s, match %s%s.", f.CVSS, f.KEV, cmp.Or(f.SSVCExploitation, "n/a"), f.EPSS, p.Exposure, p.Criticality, cmp.Or(f.Match, "unknown"), imageNote(f)),
		Action:    action,
		Method:    MethodFallback,
	}
}

// upgradeAction leads with the fix for the deployed version (each version
// of a union) and lists the other fixed branches after it.
func upgradeAction(c match.Constraint, f finding.Finding) string {
	all := "Check the deployed version; upgrade to a fixed version (" + strings.Join(f.Fixed, ", ") + ") if affected."
	if c.Any() || c.String() == "" {
		return all
	}
	alts := c.Alternatives()
	var targets, used []string
	for _, alt := range alts {
		t, _ := match.UpgradeTarget(alt, [][]string{f.Fixed})
		if t == "" {
			continue
		}
		used = append(used, t)
		if len(alts) > 1 {
			t = alt.String() + " to " + t
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return all
	}
	s := "Upgrade "
	if len(alts) == 1 {
		s += "to "
	}
	s += strings.Join(targets, " and ")
	if f.Match != string(match.Affected) {
		s = "Check the deployed version; u" + strings.TrimPrefix(s, "U") + " if affected"
	}
	if others := slices.DeleteFunc(slices.Clone(f.Fixed), func(v string) bool { return slices.Contains(used, v) }); len(others) > 0 {
		s += " (other fixed branches: " + strings.Join(others, ", ") + ")"
	}
	return s + "."
}

func notAffected(it Item) Result {
	return Result{
		Relevant:  "no",
		Priority:  "P4",
		Summary:   cmp.Or(it.Finding.Title, it.Finding.ID),
		Reasoning: it.Finding.MatchDetail,
		Action:    "No action: the configured versions are not affected.",
		Method:    MethodRules,
	}
}

func imageNote(f finding.Finding) string {
	switch {
	case f.ImageOnly():
		return ", only in a running image (no advisory for the product)"
	case f.Confirmed():
		return ", confirmed in a running image"
	}
	return ""
}
