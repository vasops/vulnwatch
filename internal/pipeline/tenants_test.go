package pipeline

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/triage"
)

// countingSource counts fetches per product.
type countingSource struct {
	fakeSource
	mu    sync.Mutex
	calls map[string]int
}

func (c *countingSource) Fetch(ctx context.Context, sel sources.Selector, since time.Time) ([]finding.Finding, error) {
	c.mu.Lock()
	c.calls[sel.Product]++
	c.mu.Unlock()
	return c.fakeSource.Fetch(ctx, sel, since)
}

// clusterSource is an in-cluster source (like Trivy).
type clusterSource struct{ fakeImageSource }

func (c *clusterSource) InCluster() bool { return true }

// keyCompleter answers every item in the prompt with P2 and records the
// finding IDs and prompts.
type keyCompleter struct{ ids, prompts []string }

var (
	keyRe = regexp.MustCompile(`"key": "([^"]+)"`)
	idRe  = regexp.MustCompile(`"id": "([^"]+)"`)
)

func (c *keyCompleter) Complete(_ context.Context, _, user string, _ map[string]any) (string, error) {
	c.prompts = append(c.prompts, user)
	for _, m := range idRe.FindAllStringSubmatch(user, -1) {
		c.ids = append(c.ids, m[1])
	}
	var res []string
	for _, m := range keyRe.FindAllStringSubmatch(user, -1) {
		res = append(res, fmt.Sprintf(`{"key":%q,"relevant":"yes","priority":"P2","summary":"s","reasoning":"r","action":"a"}`, m[1]))
	}
	return `{"results":[` + strings.Join(res, ",") + `]}`, nil
}

// scopedProducts resolves every scope of a stack like the CLI does.
func scopedProducts(t *testing.T, cfg *config.Config, yml string) []catalog.Product {
	t.Helper()
	stack, err := config.ParseStack([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	var out []catalog.Product
	for _, sc := range stack.Scopes() {
		ps, err := catalog.Resolve(cfg, sc.Stack)
		if err != nil {
			t.Fatal(err)
		}
		for i := range ps {
			ps[i].Scope = sc.Scope
		}
		out = append(out, ps...)
	}
	return out
}

func TestTenants(t *testing.T) {
	e := setup(t)
	e.cfg.Sources.Trivy = config.TrivySource{Enabled: true, MinSeverity: "critical", MinSeverityInternet: "high", MinEPSS: 0.1}
	e.products = scopedProducts(t, e.cfg, `
tenant: vasops
environment: prod
products:
  keycloak: {version: '26.x', exposure: internet}
tenants:
  acme:
    defaults: {exposure: internet}
    environments:
      prod:
        products: {keycloak: '26.1.0'}
      stage:
        products: {keycloak: '26.1.0'}
  globex:
    environments:
      prod:
        products: {keycloak: '25.0.0'}
`)
	orig := e.src[0].(*fakeSource)
	ghsa := &countingSource{fakeSource: fakeSource{name: orig.name, fs: orig.fs, err: orig.err}, calls: map[string]int{}}
	trivy := &clusterSource{fakeImageSource{fakeSource: fakeSource{name: finding.SourceTrivy, fs: []finding.Finding{
		imageFinding("CVE-2026-60", "keycloak", "critical", 9.8, "1.1", e.now),
	}}}}
	e.src = []sources.Source{ghsa, trivy}
	c := &keyCompleter{}
	cfg := e.cfg.Triage
	cfg.Enabled = true
	rep, err := e.run(t, func(o *Options) { o.Triager = triage.New(cfg, c, slog.New(slog.NewTextHandler(io.Discard, nil))) })
	if err != nil {
		t.Fatal(err)
	}

	if ghsa.calls["keycloak"] != 1 {
		t.Errorf("keycloak runs in three scopes but must be fetched once: %v", ghsa.calls)
	}
	if !rep.MultiTenant || len(rep.Scopes) != 4 || rep.Scopes[0].String() != "vasops/prod" || rep.Scopes[0].Remote {
		t.Fatalf("scopes: %+v", rep.Scopes)
	}

	// The advisory affects 26.x (vasops) and 26.1.0 (acme), not 25.0.0 (globex).
	var got []string
	for _, it := range rep.Items() {
		got = append(got, it.Scope+" "+it.Product+" "+it.ID)
	}
	if strings.Join(got, "; ") != "acme/prod keycloak CVE-2026-1; acme/stage keycloak CVE-2026-1; vasops/prod keycloak CVE-2026-1" {
		t.Fatalf("items: %v", got)
	}

	// acme's prod and stage run the same version with the same settings:
	// Claude is asked once for both. vasops runs 26.x: asked separately.
	adv := slices.DeleteFunc(slices.Clone(c.ids), func(id string) bool { return id != "CVE-2026-1" })
	if len(adv) != 2 {
		t.Fatalf("triaged IDs: %v", c.ids)
	}
	// Tenants, environments and image registries stay out of the prompt.
	for _, p := range c.prompts {
		for _, leak := range []string{"acme", "globex", "vasops", "stage", "quay.io"} {
			if strings.Contains(p, leak) {
				t.Fatalf("prompt contains %q:\n%s", leak, p)
			}
		}
	}
	if !slices.Contains(c.ids, "CVE-2026-60") || !strings.Contains(strings.Join(c.prompts, ""), "in keycloak:1") {
		t.Fatalf("the image finding is triaged with its image name: %v", c.ids)
	}
	for _, it := range rep.Items() {
		if !it.Triaged || it.Priority != "P2" {
			t.Fatalf("every scope gets the verdict: %+v", it)
		}
	}

	// Trivy reads the local cluster: its findings never reach a tenant.
	for _, it := range rep.Open {
		if it.ID == "CVE-2026-60" && it.Tenant != "vasops" {
			t.Fatalf("image finding in a tenant's scope: %+v", it)
		}
	}
	if !slices.ContainsFunc(rep.Open, func(it report.OpenItem) bool { return it.ID == "CVE-2026-60" && it.Tenant == "vasops" }) {
		t.Fatalf("the local stack keeps its image finding: %+v", rep.Open)
	}

	// State keys: plain names for the local stack (as before tenants), the
	// scope prefix for tenants.
	recs, err := e.store.ListReported(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range recs {
		keys = append(keys, r.Product+"/"+r.ID)
	}
	slices.Sort(keys)
	if !slices.Contains(keys, "keycloak/CVE-2026-1") || !slices.Contains(keys, "acme/prod/keycloak/CVE-2026-1") {
		t.Fatalf("state keys: %v", keys)
	}
}

// panicSource panics like a parser hitting data it doesn't expect.
type panicSource struct{}

func (panicSource) Name() string { return "broken" }
func (panicSource) Fetch(context.Context, sources.Selector, time.Time) ([]finding.Finding, error) {
	panic("unexpected data")
}

func TestPanickingSourceIsAWarning(t *testing.T) {
	e := setup(t)
	e.src = append(e.src[:2], panicSource{})
	rep, err := e.run(t, nil)
	if err != nil {
		t.Fatalf("a panicking source must not fail the run: %v", err)
	}
	if !slices.ContainsFunc(rep.Warnings, func(w string) bool { return strings.HasPrefix(w, "broken/") && strings.Contains(w, "panic") }) {
		t.Fatalf("warnings: %v", rep.Warnings)
	}
}
