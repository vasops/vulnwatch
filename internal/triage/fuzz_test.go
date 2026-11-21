package triage

import (
	"slices"
	"strings"
	"testing"
)

// The model's answer is untrusted output.
func FuzzValidate(f *testing.F) {
	keys := []string{"keycloak/CVE-1"}
	f.Add(`{"results":[{"key":"keycloak/CVE-1","relevant":"yes","priority":"P2","summary":"s","reasoning":"r","action":"a"}]}`)
	f.Add("```json\n{\"results\":[]}\n```")
	f.Add(`{"results":[{"key":"keycloak/CVE-1"}]} {}`)
	f.Add(``)
	f.Add(`{"results":[{"key":"keycloak/CVE-1","relevant":"yes","priority":"P2","summary":"s","reasoning":"r","action":" "}]}`)
	f.Fuzz(func(t *testing.T, raw string) {
		// With an error, res still holds the valid results.
		res, _ := Validate(raw, keys)
		for k, r := range res {
			if k != keys[0] || !slices.Contains(Priorities, r.Priority) || !slices.Contains(Relevances, r.Relevant) || strings.TrimSpace(r.Action) == "" {
				t.Fatalf("accepted an invalid result: %q %+v", k, r)
			}
		}
	})
}
