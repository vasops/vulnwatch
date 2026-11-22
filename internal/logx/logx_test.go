package logx

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditLevel(t *testing.T) {
	var buf bytes.Buffer
	lvl, err := ParseLevel("audit")
	if err != nil {
		t.Fatal(err)
	}
	log, err := New(&buf, "json", lvl)
	if err != nil {
		t.Fatal(err)
	}
	log.Info("progress")
	Audit(context.Background(), log, "finding reported", "id", "CVE-1")
	log.Warn("source failed")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit level keeps audit and warn, not info:\n%s", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil || rec["level"] != "AUDIT" || rec["id"] != "CVE-1" {
		t.Fatalf("audit record: %v %v", rec, err)
	}
	if _, err := ParseLevel("verbose"); err == nil {
		t.Fatal("unknown level must fail")
	}
	if _, err := New(&buf, "xml", lvl); err == nil {
		t.Fatal("unknown format must fail")
	}
}
