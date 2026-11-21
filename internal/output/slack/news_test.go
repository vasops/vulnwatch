package slack

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/news"
)

func TestPostNews(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o, err := New(config.SlackOutput{BaseURL: srv.URL + "/", MaxSectionText: 3000},
		Settings{Token: "xoxb-test", Channel: "CDIGEST", NewsChannel: "CNEWS"}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	o.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	it := news.Item{
		Feed: "Red Hat Security Bulletins", ID: "RHSB-2026-018",
		Title: "RHSB-2026-018 Remote Code Execution - OpenJDK (CVE-2026-114938) - <java4shell>",
		Link:  "https://access.redhat.com/security/vulnerabilities/RHSB-2026-018",
		CVEs:  []string{"CVE-2026-114938"},
	}
	sc := func(tenant, env string) config.Scope {
		return config.Scope{Tenant: tenant, Environment: env, Remote: true}
	}
	hits := []news.Hit{{Product: "java", Scopes: []config.Scope{sc("acme", "infra"), sc("acme", "prod"), sc("vasops", "prod")}}}
	if err := o.PostNews(context.Background(), it, hits); err != nil {
		t.Fatal(err)
	}
	m := *msgs
	if len(m) != 1 || m[0].Channel != "CNEWS" {
		t.Fatalf("messages: %+v", m)
	}
	text := blockText(m[0].Blocks)
	for _, want := range []string{
		":newspaper: *<https://access.redhat.com/security/vulnerabilities/RHSB-2026-018|RHSB-2026-018 Remote Code Execution - OpenJDK (CVE-2026-114938) - &lt;java4shell&gt;>*",
		"_Red Hat Security Bulletins_ · CVE-2026-114938",
		":round_pushpin: *Runs here:* *java* (acme: infra, prod; vasops: prod)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q\n%s", want, text)
		}
	}
}

func TestPostNewsFallsBackToChannel(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	o := newOutput(t, srv.URL, "", "")
	if err := o.PostNews(context.Background(), news.Item{Feed: "CISA Alerts", ID: "1", Title: "Critical Java Vulnerability"}, nil); err != nil {
		t.Fatal(err)
	}
	if m := *msgs; len(m) != 1 || m[0].Channel != "CDIGEST" || strings.Contains(blockText(m[0].Blocks), "Runs here") {
		t.Fatalf("messages: %+v", m)
	}
}
