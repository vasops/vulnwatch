package jsonout

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestRenderTriageUsage(t *testing.T) {
	render := func(rep report.Report) string {
		var buf bytes.Buffer
		if err := New("-", &buf).Render(context.Background(), rep); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	rep := reporttest.Sample()
	if strings.Contains(render(rep), "triage_usage") {
		t.Error("triage_usage is absent without usage")
	}
	rep.TriageUsage = &report.TriageUsage{Model: "claude-test", Requests: 2, InputTokens: 10, OutputTokens: 5}
	var back report.Report
	if err := json.Unmarshal([]byte(render(rep)), &back); err != nil || back.TriageUsage == nil || *back.TriageUsage != *rep.TriageUsage {
		t.Fatalf("usage round trip: %v %+v", err, back.TriageUsage)
	}
	if !strings.Contains(render(rep), `"cache_read_input_tokens": 0`) {
		t.Error("every token count is written, zeros included")
	}
}
