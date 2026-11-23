package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scenario: Chybějící routing key selhává na startu (buildOutputs), run se
// vůbec nespustí.
func TestRunPagerDutyMissingRoutingKeyEnvFailsAtStartup(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	appCfg := filepath.Join(dir, "app.yaml")
	if err := os.WriteFile(appCfg, []byte("outputs:\n  pagerduty:\n    routing_key_env: PAGERDUTY_ROUTING_KEY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, nil, "run", "--config", stack,
		"--app-config", "../../defaults/config.yaml", "--app-config", appCfg, "--output", "pagerduty", "--dry-run")
	if code == 0 || !strings.Contains(errOut, "PAGERDUTY_ROUTING_KEY") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
