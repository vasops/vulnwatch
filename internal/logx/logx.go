// Package logx sets up vulnwatch's structured logs (log/slog): text or JSON,
// and the levels debug, info, audit, warn and error.
//
// audit sits between info and warn: the record of what vulnwatch decided
// and sent (findings reported with their priority, Slack messages, state
// written). --log-level audit keeps that trail and the problems, without
// the progress messages.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// LevelAudit is between info (0) and warn (4).
const LevelAudit slog.Level = 2

// Levels are the accepted --log-level values, most verbose first.
var Levels = []string{"debug", "info", "audit", "warn", "error"}

// Formats are the accepted --log-format values.
var Formats = []string{"json", "text"}

// ParseLevel reads a level name (case-insensitive).
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "audit":
		return LevelAudit, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("want one of %s, got %q", strings.Join(Levels, ", "), s)
}

// New returns a logger writing format ("json" or "text") at level and above.
func New(w io.Writer, format string, level slog.Level) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: levelName}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("want one of %s, got %q", strings.Join(Formats, ", "), format)
}

// levelName writes the audit level as "AUDIT" instead of slog's "INFO+2".
func levelName(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		if l, ok := a.Value.Any().(slog.Level); ok && l == LevelAudit {
			a.Value = slog.StringValue("AUDIT")
		}
	}
	return a
}

// Audit logs at the audit level.
func Audit(ctx context.Context, log *slog.Logger, msg string, args ...any) {
	log.Log(ctx, LevelAudit, msg, args...)
}
