package stdout

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

var update = flag.Bool("update", false, "update golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("%s mismatch (run go test -update)\n--- got ---\n%s", name, got)
	}
}

func TestGolden(t *testing.T) {
	golden(t, "report.golden", New(nil, false).Text(reporttest.Sample()))
	golden(t, "empty.golden", New(nil, false).Text(reporttest.Empty()))
}

func TestColor(t *testing.T) {
	out := New(nil, true).Text(reporttest.Sample())
	if !strings.Contains(out, "\x1b[31m") {
		t.Fatal("no color codes")
	}
	if strings.Contains(New(nil, false).Text(reporttest.Sample()), "\x1b[") {
		t.Fatal("color codes in plain mode")
	}
}
