package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

type posted struct {
	Channel  string
	ThreadTS string
	Text     string
	Blocks   []map[string]any
	Failed   bool // answered channel_not_found
}

// fakeSlack emulates chat.postMessage, replaying testdata/ok_response.json;
// posts to the fail channels get channel_not_found.
func fakeSlack(t *testing.T, rateLimitFirst bool, fail ...string) (*httptest.Server, *[]posted) {
	t.Helper()
	okTmpl, err := os.ReadFile("testdata/ok_response.json")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		msgs  []posted
		calls int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.URL.Path != "/chat.postMessage" {
			t.Errorf("path %s", r.URL.Path)
		}
		if rateLimitFirst && calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		// slack-go sends the bot token as the documented "token" form field.
		if r.Form.Get("token") != "xoxb-test" && r.Header.Get("Authorization") != "Bearer xoxb-test" {
			t.Errorf("missing bot token")
		}
		p := posted{Channel: r.Form.Get("channel"), ThreadTS: r.Form.Get("thread_ts"), Text: r.Form.Get("text")}
		if err := json.Unmarshal([]byte(r.Form.Get("blocks")), &p.Blocks); err != nil {
			t.Errorf("blocks: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if slices.Contains(fail, p.Channel) {
			p.Failed = true
			msgs = append(msgs, p)
			w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
			return
		}
		msgs = append(msgs, p)
		ts := fmt.Sprintf("1700000000.%06d", len(msgs))
		w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(string(okTmpl), "{{ts}}", ts), "{{channel}}", p.Channel)))
	}))
	return srv, &msgs
}

func newOutput(t *testing.T, url, alert, dashboard string) *Output {
	t.Helper()
	o, err := New(config.SlackOutput{BaseURL: url + "/", MaxSectionText: 3000, DashboardURL: dashboard},
		Settings{Token: "xoxb-test", Channel: "CDIGEST", AlertChannel: alert}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	o.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return o
}

// blockText collects every text in the blocks (decoded), one per line.
func blockText(blocks []map[string]any) string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if t, ok := x["text"].(string); ok {
				out = append(out, t)
			}
			for k, c := range x {
				if k != "text" || fmt.Sprint(c) != c {
					walk(c)
				}
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	for _, b := range blocks {
		walk(b)
	}
	return strings.Join(out, "\n")
}

const dashboardTmpl = "https://grafana.example/d/vulnwatch/vulnwatch?from={from}&to={to}"

func TestRenderSummaryAndP1Alerts(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", dashboardTmpl)
	rep := reporttest.Sample()
	// A P1 found by the full-history check in this run is news too.
	rep.Open[0].FirstSeen = true
	if err := o.Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	m := *msgs
	// One summary, no thread, then two P1 alerts (new finding + first seen).
	// The summary has a section each for the counts, the two findings and the tail.
	if len(m) != 3 {
		t.Fatalf("got %d messages", len(m))
	}
	for _, x := range m {
		if x.ThreadTS != "" {
			t.Fatalf("no thread replies any more: %+v", x)
		}
	}
	if m[0].Channel != "CDIGEST" || m[0].Text != "vulnwatch: 2 new or updated vulnerabilities, 4 open" || len(m[0].Blocks) != 6 {
		t.Fatalf("summary: %+v", m[0])
	}
	dash := "https://grafana.example/d/vulnwatch/vulnwatch?from=now-30d&to=now"
	summary := blockText(m[0].Blocks)
	for _, want := range []string{
		":shield: vulnwatch report · 12 Oct 2026",
		":rotating_light: *2 critical (P1) findings*, see <#CALERT>",
		"*New:* 2   :red_circle: 1   :large_blue_circle: 1",
		":red_circle: *keycloak* `26.x` · *<https://example.invalid/nvd/CVE-2026-1001|CVE-2026-1001>*",
		"      ↳ Upgrade to 26.1.4 today.",
		":large_blue_circle: *argocd* `3.x` ·",
		"_(updated: fixed version released: 3.1.8)_",
		"*Open:* 4 (new 2)   :red_circle: 2   :large_blue_circle: 2",
		"*Full history checked:* 3 products (2 new, 1 version changed)",
		"<" + dash + "|:bar_chart: Open the dashboard>",
		":warning: incomplete: source nvd failed (1 warning, see the job log)",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary missing %q\n%s", want, summary)
		}
	}
	// Header emoji shortcodes must be rendered.
	if h := m[0].Blocks[0]["text"].(map[string]any); h["emoji"] != true {
		t.Fatalf("header emoji off: %v", h)
	}

	for i, want := range [][]string{
		{":rotating_light: P1 · keycloak · CVE-2026-1001", "*CVE-2026-1001* · <https://example.invalid/nvd/CVE-2026-1001|NVD> · <https://example.invalid/gh/GHSA-abcd-efgh-ijkl|GitHub GHSA-abcd-efgh-ijkl>  ·  *keycloak* `26.x`",
			":point_right: *Upgrade to 26.1.4 today.*", "*Severity*\nCritical · CVSS 9.8", ":warning: exploited in the wild (CISA KEV)", "new"},
		{":rotating_light: P1 · keycloak · CVE-2026-0900", ":point_right: *No fix released yet: check the advisory for mitigations.*",
			"found by the full-history check", "|:bar_chart: dashboard>"},
	} {
		a := m[1+i]
		if a.Channel != "CALERT" || !strings.HasPrefix(a.Text, "P1: keycloak ") {
			t.Fatalf("alert %d: %+v", i, a)
		}
		got := blockText(a.Blocks)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("alert %d missing %q\n%s", i, w, got)
			}
		}
	}
}

func TestOldOpenP1IsNotAlertedAgain(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "CALERT", "")
	if err := o.Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	// Summary + the new P1 only; the still-open P1 was alerted before. No dashboard configured: no link.
	if len(*msgs) != 2 || strings.Contains(blockText((*msgs)[0].Blocks), "dashboard") {
		t.Fatalf("%d messages: %+v", len(*msgs), *msgs)
	}
}

func TestRenderEmptyAndRateLimit(t *testing.T) {
	srv, msgs := fakeSlack(t, true)
	defer srv.Close()
	o := newOutput(t, srv.URL, "", "")
	if err := o.Render(context.Background(), reporttest.Empty()); err != nil {
		t.Fatal(err)
	}
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0].Text, "no new vulnerabilities") {
		t.Fatalf("%+v", *msgs)
	}
}

func TestNewRequiresSettings(t *testing.T) {
	if _, err := New(config.SlackOutput{TokenEnv: "SLACK_BOT_TOKEN", ChannelEnv: "SLACK_CHANNEL"}, Settings{}, nil, nil); err == nil {
		t.Fatal("want error")
	}
}

func TestTruncateAndEscape(t *testing.T) {
	if got := truncate(strings.Repeat("a", 3100), 3000); len([]rune(got)) != 3000 {
		t.Fatal(len(got))
	}
	// Word boundary, never inside link markup.
	if got := truncate("upgrade keycloak today", 12); got != "upgrade…" {
		t.Fatal(got)
	}
	if got := truncate("see *<https://example.invalid/a/very/long/path|the advisory>* now", 40); got != "see *…" {
		t.Fatal(got)
	}
	if escape("a<b>&c") != "a&lt;b&gt;&amp;c" {
		t.Fatal(escape("a<b>&c"))
	}
}

func TestURLIDsShowTheirTitle(t *testing.T) {
	const id = "https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/"
	if got := idLink(id, "GitLab Patch Release: 19.5.1", ""); got != "*<"+id+"|GitLab Patch Release: 19.5.1>*" {
		t.Fatal(got)
	}
	if got := idLink("CVE-2026-1", "x", ""); got != "*CVE-2026-1*" {
		t.Fatal(got)
	}
}
