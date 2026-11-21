package slack

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/metrics"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

// The summary's open total is what Grafana shows: the sum of the
// findings_open metric (#25).
func TestSummaryOpenTotalMatchesMetrics(t *testing.T) {
	rep := reporttest.Sample()
	rep.Open[0].FirstSeen = true // history found in this run counts too
	fams, err := metrics.Registry(metrics.Run{Mode: rep.Mode, Report: &rep}).Gather()
	if err != nil {
		t.Fatal(err)
	}
	var open float64
	for _, f := range fams {
		if f.GetName() == "vulnwatch_findings_open" {
			for _, m := range f.GetMetric() {
				open += m.GetGauge().GetValue()
			}
		}
	}
	if open == 0 {
		t.Fatal("no findings_open series")
	}

	srv, msgs := fakeSlack(t, false)
	defer srv.Close()
	if err := newOutput(t, srv.URL, "CALERT", "").Render(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("*Open:* %d (new %d)", int(open), rep.Total()); !strings.Contains(blockText((*msgs)[0].Blocks), want) {
		t.Fatalf("summary lacks %q:\n%s", want, blockText((*msgs)[0].Blocks))
	}
}
