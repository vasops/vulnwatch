// Package html renders the report as one self-contained HTML file from an
// embedded template (inline CSS, no external assets).
package html

import (
	"bytes"
	"context"
	_ "embed"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/report"
)

//go:embed report.html.tmpl
var tmplText string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"join":  strings.Join,
	"pkgs":  func(ps []finding.Package) string { return report.PackageLine(ps, 5) },
	"imgs":  func(is []string) string { return report.UnmatchedLine(is, 20) },
	"names": report.Names,
	"pct":   func(f float64) float64 { return f * 100 },
}).Parse(tmplText))

type Output struct{ path string }

func New(path string) *Output { return &Output{path: path} }

func (o *Output) Name() string { return "html" }

// Bytes renders the report to HTML.
func Bytes(r report.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (o *Output) Render(_ context.Context, r report.Report) error {
	b, err := Bytes(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(o.path), ".vulnwatch-*.html")
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
	return os.Rename(tmp.Name(), o.path)
}
