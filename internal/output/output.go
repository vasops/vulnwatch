// Package output defines the pluggable report outputs.
package output

import (
	"context"

	"github.com/vasops/vulnwatch/internal/report"
)

// Output renders a report to one destination.
type Output interface {
	Name() string
	Render(ctx context.Context, r report.Report) error
}
