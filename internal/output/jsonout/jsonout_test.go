package jsonout

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vasops/vulnwatch/internal/report"
	"github.com/vasops/vulnwatch/internal/report/reporttest"
)

func TestRender(t *testing.T) {
	var buf bytes.Buffer
	if err := New("-", &buf).Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	var back report.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Total() != 2 || back.Groups[0].Products[0].Items[0].ID != "CVE-2026-1001" {
		t.Fatalf("round trip: %+v", back)
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if err := New(path, nil).Render(context.Background(), reporttest.Sample()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, buf.Bytes()) {
		t.Fatal("file and stdout output differ")
	}
}
