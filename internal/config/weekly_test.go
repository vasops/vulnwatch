package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlackWeekly(t *testing.T) {
	cfg := exampleConfig(t)
	if w := cfg.Outputs.Slack.Weekly; w.Enabled || w.Day != "monday" {
		t.Fatalf("default: %+v", w)
	}
	tests := []struct {
		name    string
		weekly  string
		want    time.Weekday
		wantErr bool
	}{
		{"monday", "{enabled: true, day: monday}", time.Monday, false},
		{"any case", "{enabled: true, day: Friday}", time.Friday, false},
		{"sunday", "{enabled: true, day: sunday}", time.Sunday, false},
		{"no day means monday", "{enabled: true, day: ''}", time.Monday, false},
		{"abbreviation rejected", "{enabled: true, day: mon}", 0, true},
		{"other language rejected", "{enabled: true, day: montag}", 0, true},
		{"not checked while off", "{enabled: false, day: montag}", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := exampleConfig(t, Source{"o", []byte("outputs: {slack: {weekly: " + tt.weekly + "}}")})
			err := c.Validate()
			if tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), "outputs.slack.weekly.day") {
					t.Fatalf("want a day error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d, ok := c.Outputs.Slack.Weekly.Weekday(); c.Outputs.Slack.Weekly.Enabled && (!ok || d != tt.want) {
				t.Fatalf("weekday %v %v", d, ok)
			}
		})
	}
}

// A config file written before the setting loads with the built-in
// defaults off (--no-defaults): weekly is then off, and Monday when enabled.
func TestSlackWeeklyWithoutDefaults(t *testing.T) {
	b, err := os.ReadFile(exampleConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start, end := strings.Index(s, "    # Weekly report per route"), strings.Index(s, "  webhook:")
	if start < 0 || end < start {
		t.Fatal("weekly block not found in the example config")
	}
	for _, tt := range []struct {
		name, block string
		enabled     bool
	}{
		{"no weekly block", "", false},
		{"enabled without a day", "    weekly: {enabled: true}\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(s[:start]+tt.block+s[end:]), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(LoadOptions{ConfigPaths: []string{path}, Paths: []string{exampleSources}, Getenv: func(string) string { return "" }})
			if err != nil {
				t.Fatal(err)
			}
			w := cfg.Outputs.Slack.Weekly
			if d, ok := w.Weekday(); w.Enabled != tt.enabled || w.Day != "" || !ok || d != time.Monday {
				t.Fatalf("%+v %v %v", w, d, ok)
			}
		})
	}
}
