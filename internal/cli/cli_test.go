package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/state"
	"github.com/vasops/vulnwatch/version"
)

func run(t *testing.T, env map[string]string, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	if env == nil {
		env = map[string]string{}
	}
	if _, ok := env["VULNWATCH_CONFIG"]; !ok {
		env["VULNWATCH_CONFIG"] = "../../defaults/config.yaml"
	}
	if _, ok := env["VULNWATCH_SOURCES"]; !ok {
		env["VULNWATCH_SOURCES"] = "../../defaults/sources.yaml"
	}
	// run and bootstrap would restrict the whole test process with Landlock
	// (on Linux), and every later test in it would lose file access.
	if _, ok := env["VULNWATCH_LANDLOCK"]; !ok {
		env["VULNWATCH_LANDLOCK"] = "false"
	}
	code := Execute(context.Background(), append(args, "--log-format", "text"), &out, &errOut, func(k string) string { return env[k] })
	return out.String(), errOut.String(), code
}

// The full example stack downloads Helm charts; its offline checks live in
// the config tests (TestExampleStack). This one uses its plain products.
func TestValidateConfig(t *testing.T) {
	stack := filepath.Join(t.TempDir(), "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: {version: '26.7.0', exposure: internet}\n  gitlab-ce: '19.5.1'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, nil, "validate-config", "--config", stack)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"OK:", "\nkeycloak 26.7.0  (exposure internet", "ghsa:", "keycloak/keycloak", "\ngitlab-ce "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestValidateUnknownProductSuggests(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	os.WriteFile(stack, []byte("products:\n  keycloack: '26.x'\n"), 0o600)
	_, errOut, code := run(t, nil, "validate-config", "--config", stack)
	if code == 0 || !strings.Contains(errOut, "did you mean keycloak") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestOverrideOnlyProduct(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	os.WriteFile(stack, []byte("products:\n  vmware-velero: '1.x'\n"), 0o600)
	env := map[string]string{"STACK_CONFIG": stack, "VULNWATCH_SOURCES": "../../defaults/sources.yaml,../../examples/sources-override.yaml"}
	out, errOut, code := run(t, env, "validate-config")
	if code != 0 || !strings.Contains(out, "velero 1.x") || !strings.Contains(out, "velero-io/velero") {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	out, _, _ = run(t, env, "catalog", "list")
	if !strings.Contains(out, "velero") || !strings.Contains(out, "sources.yaml + ../../examples/sources-override.yaml") || !strings.Contains(out, "disabled") {
		t.Fatalf("catalog list:\n%s", out)
	}
}

func TestCatalogShowAndConfigDump(t *testing.T) {
	out, _, code := run(t, nil, "catalog", "show", "k8s")
	if code != 0 || !strings.Contains(out, "kubernetes:") {
		t.Fatalf("show: %d %s", code, out)
	}
	_, errOut, code := run(t, nil, "catalog", "show", "grafanna")
	if code == 0 || !strings.Contains(errOut, "grafana") {
		t.Fatalf("show unknown: %s", errOut)
	}
	out, _, code = run(t, map[string]string{"GITHUB_TOKEN": "ghp_secret"}, "config", "dump")
	if code != 0 || strings.Contains(out, "ghp_secret") || !strings.Contains(out, "GITHUB_TOKEN: set (redacted)") {
		t.Fatalf("dump: %s", out)
	}
}

func TestRunFlagValidation(t *testing.T) {
	env := map[string]string{"ANTHROPIC_API_KEY": "x"}
	small := filepath.Join(t.TempDir(), "stack.yaml") // no Helm charts: no downloads
	if err := os.WriteFile(small, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"run", "--config", "../../examples/stack.yaml", "--output", "stdout,json"}, "both write to stdout"},
		{[]string{"run", "--config", "../../examples/stack.yaml", "--output", "pdf"}, "unknown output"},
		{[]string{"run", "--config", "../../examples/stack.yaml", "--output", "slack"}, "SLACK_BOT_TOKEN"},
		{[]string{"run", "--config", "../../examples/stack.yaml", "--since", "yesterday"}, "--since"},
		{[]string{"run", "--config", small, "--product", "grafana", "--dry-run"}, "not in"},
	}
	for _, c := range cases {
		_, errOut, code := run(t, env, c.args...)
		if code == 0 || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: exit %d, stderr %q", c.args, code, errOut)
		}
	}
	// Enable triage explicitly: the example file may have it switched off.
	triageOn := filepath.Join(t.TempDir(), "triage.yaml")
	if err := os.WriteFile(triageOn, []byte("triage: {enabled: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, nil, "run", "--config", "../../examples/stack.yaml", "--dry-run",
		"--app-config", "../../defaults/config.yaml", "--app-config", triageOn)
	if code == 0 || !strings.Contains(errOut, "ANTHROPIC_API_KEY") {
		t.Errorf("missing API key: %d %s", code, errOut)
	}
}

// A run that fails after the config is loaded but before the pipeline still
// reports run_success=0, health-only (POST), so the last report's findings
// stay on the Pushgateway.
func TestStartupFailurePushesMetrics(t *testing.T) {
	var method, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	appCfg := filepath.Join(dir, "app.yaml")
	metricsFile := filepath.Join(dir, "vulnwatch.prom")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appCfg, []byte("triage: {enabled: true}\nmetrics: {pushgateway_url: '"+srv.URL+"'}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, map[string]string{"STATE_DB": filepath.Join(dir, "s.db")}, "run", "--config", stack,
		"--app-config", "../../defaults/config.yaml", "--app-config", appCfg, "--metrics-file", metricsFile)
	if code == 0 || !strings.Contains(errOut, "ANTHROPIC_API_KEY") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if method != http.MethodPost || !strings.Contains(body, "vulnwatch_run_success") || strings.Contains(body, "vulnwatch_findings_open") {
		t.Fatalf("push: %s (%d bytes)", method, len(body))
	}
	b, _ := os.ReadFile(metricsFile)
	if !strings.Contains(string(b), `vulnwatch_run_success{mode="run"} 0`) {
		t.Fatalf("metrics file:\n%s", b)
	}
}

func TestVersion(t *testing.T) {
	out, _, code := run(t, nil, "version")
	if code != 0 || !strings.HasPrefix(out, "vulnwatch "+version.Version+" (commit ") {
		t.Fatal(out)
	}
}

func TestBuiltinDefaults(t *testing.T) {
	noFiles := map[string]string{"VULNWATCH_CONFIG": "", "VULNWATCH_SOURCES": ""}
	out, errOut, code := run(t, noFiles, "catalog", "list")
	if code != 0 || !strings.Contains(out, "keycloak") || !strings.Contains(out, "built-in sources.yaml") {
		t.Fatalf("built-in defaults alone: %d %s %s", code, out, errOut)
	}
	out, errOut, code = run(t, noFiles, "catalog", "list", "--sources", "../../examples/sources-override.yaml")
	if code != 0 || !strings.Contains(out, "velero") || !strings.Contains(out, "built-in sources.yaml + ../../examples/sources-override.yaml") {
		t.Fatalf("override over the built-in sources: %d %s %s", code, out, errOut)
	}
	_, errOut, code = run(t, noFiles, "catalog", "list", "--no-defaults")
	if code == 0 || !strings.Contains(errOut, "--app-config") || !strings.Contains(errOut, "built-in defaults are off") {
		t.Fatalf("--no-defaults without files should fail clearly: %d %s", code, errOut)
	}
	_, errOut, code = run(t, map[string]string{"VULNWATCH_NO_DEFAULTS": "true", "VULNWATCH_CONFIG": "../../defaults/config.yaml", "VULNWATCH_SOURCES": ""}, "catalog", "list")
	if code == 0 || !strings.Contains(errOut, "--sources") {
		t.Fatalf("VULNWATCH_NO_DEFAULTS without a sources file should fail: %d %s", code, errOut)
	}
	for kind, file := range map[string]string{"config": "../../defaults/config.yaml", "sources": "../../defaults/sources.yaml"} {
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		out, errOut, code = run(t, nil, "config", "defaults", kind)
		if code != 0 || out != string(want) {
			t.Fatalf("config defaults %s differs from %s: %d %s", kind, file, code, errOut)
		}
	}
}

func TestHelmWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	write := func(s string) {
		if err := os.WriteFile(stack, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := map[string]string{"STACK_CONFIG": stack, "STATE_DB": filepath.Join(dir, "s.db")}

	// An unmapped chart with explicit versions needs no download.
	write("helm:\n  - {repo: https://example.invalid, chart: cluster, version: 0.9.0, versions: {postgres: '17.4'}}\n")
	out, errOut, code := run(t, env, "validate-config")
	if code != 0 || !strings.Contains(out, "postgresql 17.4") || !strings.Contains(out, "cluster 0.9.0 (override)") {
		t.Fatalf("override-only release: %d %s %s", code, out, errOut)
	}

	write("helm:\n  - {repo: https://example.invalid, chart: unknown-chart, version: 1.0.0}\n")
	_, errOut, code = run(t, env, "validate-config")
	if code == 0 || !strings.Contains(errOut, `chart "unknown-chart" has no helm_charts mapping`) {
		t.Fatalf("unmapped chart: %d %s", code, errOut)
	}
}

func TestBootstrapSkipIfInitialized(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "s.db")
	stack := filepath.Join(dir, "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st, err := state.Open(ctx, db, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, time.Now(), nil, nil, true); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// Initialized: returns at once, without network or outputs.
	out, errOut, code := run(t, map[string]string{"STATE_DB": db, "STACK_CONFIG": stack}, "bootstrap", "--skip-if-initialized", "--log-format", "text")
	if code != 0 || out != "" || !strings.Contains(errOut, "bootstrap skipped") {
		t.Fatalf("exit %d out %q err %q", code, out, errOut)
	}
}

func TestAuditFlags(t *testing.T) {
	_, errOut, code := run(t, nil, "audit", "--version", "26.4.0")
	if code == 0 || !strings.Contains(errOut, "--version needs exactly one --product") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	_, errOut, code = run(t, nil, "audit", "--product", "keycloak", "--version", ">=27 <26")
	if code == 0 || !strings.Contains(errOut, "--version") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(prev) })
	if _, errOut, code := run(t, map[string]string{"VULNWATCH_MEMORY_LIMIT": "1073741824"}, "version"); code != 0 {
		t.Fatal(errOut)
	}
	if got := debug.SetMemoryLimit(-1); got != 1073741824/10*9 {
		t.Fatalf("soft limit %d, want 90%% of 1Gi", got)
	}
	debug.SetMemoryLimit(prev)
	run(t, map[string]string{"VULNWATCH_MEMORY_LIMIT": "1073741824", "GOMEMLIMIT": "100MiB"}, "version")
	if got := debug.SetMemoryLimit(-1); got != prev {
		t.Fatalf("an explicit GOMEMLIMIT wins, got %d", got)
	}
}
