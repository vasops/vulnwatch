package metrics

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// chartAlert is one alert rule of templates/prometheusrule.yaml.
type chartAlert struct {
	name, block string
}

// findingAlerts returns the alerts the chart renders with its default
// values (findingAlerts: true) in the block guarded by that value. helm is
// not a dependency of the module, so the template is read as text: alert
// expressions only use the $sel selector, which the test ignores.
func findingAlerts(t *testing.T) []chartAlert {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "charts", "vulnwatch", "templates", "prometheusrule.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	vals, err := os.ReadFile(filepath.Join("..", "..", "charts", "vulnwatch", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s+findingAlerts: true\b`).Match(vals) {
		t.Fatal("values.yaml: findingAlerts is no longer true by default")
	}
	s := string(b)
	start := strings.Index(s, "{{- if $r.findingAlerts }}")
	if start < 0 {
		t.Fatal("no findingAlerts block in prometheusrule.yaml")
	}
	s = s[start:]
	if end := strings.Index(s, "{{- end }}"); end >= 0 {
		s = s[:end]
	}
	var out []chartAlert
	parts := strings.Split(s, "- alert: ")
	for _, p := range parts[1:] {
		name, _, _ := strings.Cut(p, "\n")
		out = append(out, chartAlert{name: strings.TrimSpace(name), block: p})
	}
	return out
}

// publicExploitAlert is the alert over findings_open_public_exploit.
func publicExploitAlert(t *testing.T, alerts []chartAlert) chartAlert {
	t.Helper()
	for _, a := range alerts {
		expr, _, _ := strings.Cut(a.block, "labels:")
		if strings.Contains(expr, "vulnwatch_findings_open_public_exploit") {
			return a
		}
	}
	t.Fatal("no alert over vulnwatch_findings_open_public_exploit in the findingAlerts block")
	return chartAlert{}
}

// Scenario: alert na veřejný exploit. With the default values the chart has
// its own warning alert over findings_open_public_exploit; its expression
// leaves out products the KEV alert (or the P1 alert) already reports.
func TestPublicExploitAlert(t *testing.T) {
	alerts := findingAlerts(t)
	a := publicExploitAlert(t, alerts)
	for _, existing := range []string{"VulnwatchExploitedVulnerabilityOpen", "VulnwatchP1Open"} {
		if a.name == existing {
			t.Fatalf("the public exploit alert must be its own alert, not %s", existing)
		}
	}
	if !strings.Contains(a.block, "severity: warning") {
		t.Errorf("%s: want severity warning:\n%s", a.name, a.block)
	}
	expr, _, _ := strings.Cut(a.block, "labels:")
	main, rest, ok := strings.Cut(expr, "unless")
	if !ok {
		t.Fatalf("%s: the expression excludes nothing (no unless):\n%s", a.name, expr)
	}
	if !strings.Contains(main, "vulnwatch_findings_open_public_exploit") {
		t.Errorf("%s: public exploit must be what it alerts on, before unless:\n%s", a.name, expr)
	}
	if !strings.Contains(rest, "vulnwatch_findings_open_kev") {
		t.Errorf("%s: must stay quiet where the KEV alert fires (findings_open_kev after unless):\n%s", a.name, expr)
	}
	if !strings.Contains(rest, `priority="P1"`) {
		t.Errorf("%s: must stay quiet where the P1 alert fires (findings_open priority P1 after unless):\n%s", a.name, expr)
	}
	if !strings.Contains(rest, "on (job, instance, tenant, environment, product)") {
		t.Errorf("%s: must match per product like VulnwatchExploitedVulnerabilityOpen:\n%s", a.name, expr)
	}
	for _, kept := range []string{"VulnwatchExploitedVulnerabilityOpen", "VulnwatchP1Open"} {
		found := false
		for _, x := range alerts {
			found = found || x.name == kept
		}
		if !found {
			t.Errorf("alert %s is gone", kept)
		}
	}
}

// VulnwatchP1Open's description and the chart README say the new alert is
// quiet for the product too; the README row of the new alert says it is
// quiet where KEV or P1 alerts.
func TestPublicExploitAlertDocumented(t *testing.T) {
	alerts := findingAlerts(t)
	name := publicExploitAlert(t, alerts).name
	for _, a := range alerts {
		if a.name == "VulnwatchP1Open" && !strings.Contains(a.block, name) {
			t.Errorf("VulnwatchP1Open description does not say %s stays quiet:\n%s", name, a.block)
		}
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "charts", "vulnwatch", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if m := regexp.MustCompile("^\\|\\s*`(Vulnwatch\\w+)`\\s*\\|").FindStringSubmatch(l); m != nil {
			rows[m[1]] = l
		}
	}
	row, ok := rows[name]
	if !ok {
		t.Fatalf("charts/vulnwatch/README.md: no row for %s", name)
	}
	if !strings.Contains(row, "VulnwatchExploitedVulnerabilityOpen") || !strings.Contains(row, "VulnwatchP1Open") {
		t.Errorf("README row of %s must say it is quiet where the KEV and P1 alerts fire: %s", name, row)
	}
	if !strings.Contains(rows["VulnwatchP1Open"], name) {
		t.Errorf("README row of VulnwatchP1Open must say %s is quiet for the product: %s", name, rows["VulnwatchP1Open"])
	}
}
