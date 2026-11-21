package slack

import (
	"context"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestFixedInLeadsWithUpgradeTarget(t *testing.T) {
	for _, tc := range []struct {
		constraint string
		fixed      []string
		want       string
	}{
		{"3.x", []string{"3.1.8", "3.0.15"}, "3.0.15 (also 3.1.8)"},
		{"26.7.0", []string{"26.7.5"}, "26.7.5"},
		{"26.7.0 || 20.0.3", []string{"25.0.1", "26.7.5", "20.0.5"}, "26.7.0 → 26.7.5, 20.0.3 → 20.0.5 (also 25.0.1)"},
		{"26.7.0", []string{"25.0.1"}, "25.0.1"}, // no fix above ours: listed as is
		{"*", []string{"1.0.1", "1.0.0"}, "1.0.1, 1.0.0"},
	} {
		if got := fixedIn(tc.constraint, tc.fixed); got != tc.want {
			t.Errorf("fixedIn(%q, %v) = %q, want %q", tc.constraint, tc.fixed, got, tc.want)
		}
	}
}

// The card shows KEV and EPSS together, history cards included (#27).
func TestCardShowsKEVAndEPSS(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	rep := reporttest.Sample()
	rep.Open[0].FirstSeen = true // the keycloak P1, sorted first
	rep.Open[0].EPSS = 0.05
	if err := newOutput(t, srv.URL, "CALERT", "").Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if len(*msgs) != 3 {
		t.Fatalf("%d messages", len(*msgs))
	}
	for i, want := range []string{
		"*Exploitation*\n:warning: exploited in the wild (CISA KEV)\nEPSS 91.2% (probability in 30 days)",
		"*Exploitation*\n:warning: exploited in the wild (CISA KEV)\nEPSS 5.0% (probability in 30 days)",
	} {
		if got := blockText((*msgs)[1+i].Blocks); !strings.Contains(got, want) {
			t.Errorf("card %d lacks %q:\n%s", i, want, got)
		}
	}
	if got := blockText((*msgs)[1].Blocks); !strings.Contains(got, "*Fixed in*\n26.1.4") {
		t.Errorf("fixed in:\n%s", got)
	}
}

// The card shows Red Hat's rating with the severity and its statement,
// escaped like all advisory text.
func TestCardShowsRedHat(t *testing.T) {
	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	rep := reporttest.Sample()
	it := &rep.Groups[0].Products[0].Items[0] // the keycloak P1
	it.RedHatSeverity = "important"
	it.RedHatStatement = "Only with the <admin> console exposed."
	if err := newOutput(t, srv.URL, "CALERT", "").Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	got := blockText((*msgs)[1].Blocks)
	for _, want := range []string{"CVSS 9.8\nRed Hat: important", "_Red Hat:_ Only with the &lt;admin&gt; console exposed."} {
		if !strings.Contains(got, want) {
			t.Errorf("card lacks %q:\n%s", want, got)
		}
	}
}
