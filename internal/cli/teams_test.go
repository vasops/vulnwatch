package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scenario: Chybějící hlavní URL selhává na startu (buildOutputs), run se
// vůbec nespustí.
func TestRunTeamsMissingURLEnvFailsAtStartup(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	appCfg := filepath.Join(dir, "app.yaml")
	if err := os.WriteFile(appCfg, []byte("outputs:\n  teams:\n    url_env: TEAMS_URL\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, nil, "run", "--config", stack,
		"--app-config", "../../defaults/config.yaml", "--app-config", appCfg, "--output", "teams", "--dry-run")
	if code == 0 || !strings.Contains(errOut, "TEAMS_URL") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
