package cli

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/sandbox"
)

// Below Landlock ABI 4 the TCP rules are dropped; the log must not claim them.
func TestLandlockLogArgs(t *testing.T) {
	ports := []uint16{443, 9091}
	for abi, want := range map[int]string{
		3: "[abi 3 tcp_enforced false]",
		4: "[abi 4 tcp_enforced true tcp_ports [443 9091]]",
		6: "[abi 6 tcp_enforced true tcp_ports [443 9091]]",
	} {
		if got := fmt.Sprint(landlockLogArgs(abi, ports)); got != want {
			t.Errorf("abi %d: %s, want %s", abi, got, want)
		}
	}
}

func TestParseLandlock(t *testing.T) {
	for in, want := range map[string]string{
		"": landlockBestEffort, "true": landlockBestEffort, "1": landlockBestEffort, "YES": landlockBestEffort,
		"false": landlockOff, "0": landlockOff, "no": landlockOff,
		"require": landlockRequire, "Require": landlockRequire,
	} {
		if got, err := parseLandlock(in); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := parseLandlock("strict"); err == nil {
		t.Error("an unknown mode must be an error")
	}
}

// stubLandlock makes restrict see the given ABI without restricting the
// test process; it reports whether Apply was called.
func stubLandlock(t *testing.T, abi int) *bool {
	t.Helper()
	called := new(bool)
	orig := applyLandlock
	applyLandlock = func(sandbox.Spec) (int, error) { *called = true; return abi, nil }
	t.Cleanup(func() { applyLandlock = orig })
	return called
}

// Without Landlock in the kernel, require fails the run, best effort warns.
func TestRestrictModes(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		abi     int
		wantErr bool
		wantLog string
	}{
		{"require", 0, true, ""},
		{"true", 0, false, "level=WARN msg=\"landlock not available"},
		{"require", 6, false, "level=INFO msg=\"landlock applied\" abi=6"},
		{"true", 6, false, "level=INFO msg=\"landlock applied\" abi=6"},
		{"false", 0, false, "landlock off"},
		{"bogus", 6, true, ""},
	} {
		called := stubLandlock(t, tc.abi)
		var logs bytes.Buffer
		a := &app{landlock: tc.mode, configPath: "/nonexistent/stack.yaml", getenv: func(string) string { return "" },
			log: slog.New(slog.NewTextHandler(&logs, nil))}
		err := a.restrict(&config.Config{}, outputFlags{})
		if (err != nil) != tc.wantErr {
			t.Errorf("%s, abi %d: err %v, want error %v", tc.mode, tc.abi, err, tc.wantErr)
		}
		if !strings.Contains(logs.String(), tc.wantLog) {
			t.Errorf("%s, abi %d: log %q, want %q", tc.mode, tc.abi, logs.String(), tc.wantLog)
		}
		if *called != (tc.mode != "false" && tc.mode != "bogus") {
			t.Errorf("%s: Apply called %v", tc.mode, *called)
		}
	}
}

// VULNWATCH_LANDLOCK=require without Landlock fails the run on the usual
// failure path: run_success=0 in the metrics.
func TestLandlockRequiredFailsRun(t *testing.T) {
	stubLandlock(t, 0)
	dir := t.TempDir()
	stack := filepath.Join(dir, "stack.yaml")
	appCfg := filepath.Join(dir, "app.yaml")
	metricsFile := filepath.Join(dir, "vulnwatch.prom")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appCfg, []byte("triage: {enabled: false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"STATE_DB": filepath.Join(dir, "s.db"), "VULNWATCH_LANDLOCK": "require"}
	_, errOut, code := run(t, env, "run", "--dry-run", "--config", stack,
		"--app-config", "../../defaults/config.yaml", "--app-config", appCfg, "--metrics-file", metricsFile)
	if code == 0 || !strings.Contains(errOut, "landlock: not available") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	b, _ := os.ReadFile(metricsFile)
	if !strings.Contains(string(b), `vulnwatch_run_success{mode="run"} 0`) {
		t.Fatalf("metrics file:\n%s", b)
	}
}
