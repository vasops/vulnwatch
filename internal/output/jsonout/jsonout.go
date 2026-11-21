// Package jsonout writes the report model as JSON to stdout or a file.
package jsonout

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/vasops/vulnwatch/internal/report"
)

type Output struct {
	path   string // "-" = stdout
	stdout io.Writer
}

func New(path string, stdout io.Writer) *Output { return &Output{path: path, stdout: stdout} }

func (o *Output) Name() string { return "json" }

func (o *Output) Render(_ context.Context, r report.Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if o.path == "-" || o.path == "" {
		_, err = o.stdout.Write(b)
		return err
	}
	return writeAtomic(o.path, b)
}

// writeAtomic writes via a temp file in the same directory and renames it.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vulnwatch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
