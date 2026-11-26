package slack

import (
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
)

func TestTriageFailureLine(t *testing.T) {
	tests := []struct {
		name string
		r    report.Report
		want string
	}{
		{"one finding", report.Report{TriageFailures: 1, TriageUntriaged: 1, TriageFailure: "Claude API error"},
			":warning: Claude gave no verdict for 1 finding (Claude API error): rule-based priority until a later run asks again"},
		{"no reason", report.Report{TriageFailures: 2, TriageUntriaged: 10},
			":warning: Claude gave no verdict for 10 findings: rule-based priority until a later run asks again"},
		{"no count", report.Report{TriageFailures: 2, TriageFailure: "invalid output"},
			":warning: Claude triage failed in 2 batches (invalid output)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triageFailureLine(tt.r); got != tt.want {
				t.Fatalf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
