package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

// The chart sets env vars by name; a renamed constant here would leave the
// pod with a variable nothing reads (e.g. a sandbox or memory limit silently
// gone). The templates are parsed as text: depguard bans os/exec (tests
// too) and the CI test image has no helm, so `helm template` would only ever
// skip there. Names from values (env, secretEnv) are the operator's, not
// part of this contract.
func TestChartEnvContract(t *testing.T) {
	reads := map[string]bool{
		envStackConfig: true, envSources: true, envAppConfig: true, envNoDefaults: true,
		envLogLevel: true, envLogFormat: true, envLandlock: true, envStateDB: true,
		envMemoryLimit: true,
		"TMPDIR":       true, // os.TempDir: Landlock's write dir, SQLite and chart downloads
	}
	files, err := filepath.Glob("../../charts/vulnwatch/templates/*")
	if err != nil || len(files) == 0 {
		t.Fatalf("chart templates: %v", err)
	}
	// "- name: STACK_CONFIG" in an env list; templated names don't match.
	nameRe := regexp.MustCompile(`(?m)^\s*-\s+name:\s+([A-Z][A-Z0-9_]*)\s*$`)
	var set []string
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // the chart's own templates
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range nameRe.FindAllSubmatch(b, -1) {
			name := string(m[1])
			set = append(set, name)
			if !reads[name] {
				t.Errorf("%s sets %s, which vulnwatch doesn't read", filepath.Base(f), name)
			}
		}
	}
	// Guards the parsing itself: these must always be found.
	for _, want := range []string{envStackConfig, envStateDB, envLandlock, envMemoryLimit} {
		if !slices.Contains(set, want) {
			t.Errorf("the chart no longer sets %s (found %v)", want, set)
		}
	}
}
