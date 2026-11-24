package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRepo(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Every metric of the table in docs/outputs.md has its own row and meaning:
// the public exploit gauge is no longer squeezed into the KEV row.
func TestOutputsDocsMetricRows(t *testing.T) {
	doc := readRepo(t, "docs", "outputs.md")
	for _, m := range []string{"vulnwatch_findings_open_kev", "vulnwatch_findings_open_public_exploit",
		"vulnwatch_findings_open_unfixed", "vulnwatch_findings_open_oldest_days"} {
		rows := 0
		for _, l := range strings.Split(doc, "\n") {
			if strings.HasPrefix(l, "| `"+m+"`") {
				rows++
				if strings.Count(l, "`vulnwatch_") > 1 || strings.Contains(l, "`…_") {
					t.Errorf("%s shares a row with other metrics: %s", m, l)
				}
			}
		}
		if rows != 1 {
			t.Errorf("%s: %d own rows in docs/outputs.md, want 1", m, rows)
		}
	}
	for _, l := range strings.Split(doc, "\n") {
		if strings.HasPrefix(l, "| `vulnwatch_finding_first_reported_timestamp_seconds`") && !strings.Contains(l, "public_exploit") {
			t.Errorf("first_reported row does not list the public_exploit label: %s", l)
		}
	}
}

// The dashboards' descriptions and the alert table mention the new panel,
// column and alert.
func TestDocsDescribePublicExploit(t *testing.T) {
	for _, f := range [][]string{{"docs", "outputs.md"}, {"charts", "vulnwatch", "README.md"}} {
		doc := readRepo(t, f...)
		if !strings.Contains(strings.ToLower(doc), "public exploit") {
			t.Errorf("%s does not mention public exploits", filepath.Join(f...))
		}
	}
	vals := readRepo(t, "charts", "vulnwatch", "README.md")
	for _, l := range strings.Split(vals, "\n") {
		if strings.Contains(l, "`metrics.prometheusRule.findingAlerts`") && !strings.Contains(l, "exploit") {
			t.Errorf("findingAlerts row does not mention the new alert: %s", l)
		}
	}
}
