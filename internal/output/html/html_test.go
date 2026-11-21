package html

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

var update = flag.Bool("update", false, "update golden files")

func TestGolden(t *testing.T) {
	cases := map[string]report.Report{"report.golden.html": reporttest.Sample(), "empty.golden.html": reporttest.Empty()}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := Bytes(rep)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name)
			if *update {
				os.WriteFile(path, got, 0o644)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("%s mismatch (run go test -update)", name)
			}
		})
	}
}

func TestSelfContainedAndEscaped(t *testing.T) {
	b, err := Bytes(reporttest.Sample())
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// The only <link> is the inline (data:) favicon.
	inline := strings.ReplaceAll(s, `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml;base64,`, "")
	for _, bad := range []string{"<script", "<link ", "@import", "src=", "http-equiv"} {
		if strings.Contains(inline, bad) {
			t.Errorf("external/active content %q in HTML", bad)
		}
	}
	if strings.Contains(s, "<redirect_uri>") || !strings.Contains(s, "&lt;redirect_uri&gt;") || !strings.Contains(s, "prefers-color-scheme") {
		t.Error("escaping or dark mode missing")
	}
	path := filepath.Join(t.TempDir(), "r.html")
	if err := New(path).Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
}
