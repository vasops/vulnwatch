// Package stdout renders the report as human-readable text, with ANSI colors
// when writing to a terminal.
package stdout

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vasops/vulnwatch/internal/report"
)

type Output struct {
	w     io.Writer
	color bool
}

// New writes to w; color enables ANSI escapes.
func New(w io.Writer, color bool) *Output { return &Output{w: w, color: color} }

// IsTerminal reports whether f is a character device (a TTY).
func IsTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func (o *Output) Name() string { return "stdout" }

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
)

var prioColor = map[string]string{"P1": red + bold, "P2": yellow + bold, "P3": blue + bold, "P4": dim}

func (o *Output) c(code, s string) string {
	if !o.color || code == "" {
		return s
	}
	return code + s + reset
}

func (o *Output) Render(_ context.Context, r report.Report) error {
	_, err := io.WriteString(o.w, o.Text(r))
	return err
}

// Text renders the report to a string.
func (o *Output) Text(r report.Report) string {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	title := "vulnwatch report"
	if r.Mode != report.ModeRun {
		title += " (" + r.Mode + ")"
	}
	p("%s\n", o.c(bold, title))
	p("Window: %s → %s\n", r.Since.Format("2006-01-02 15:04"), r.Until.Format("2006-01-02 15:04 MST"))
	if r.MultiTenant {
		per := map[string]int{}
		for _, pi := range r.Products {
			per[pi.Scope]++
		}
		var names []string
		for _, sc := range r.Scopes {
			names = append(names, fmt.Sprintf("%s (%d)", sc, per[sc.String()]))
		}
		p("Tenants: %s\n\n", strings.Join(names, ", "))
	} else {
		var names []string
		for _, pi := range r.Products {
			names = append(names, pi.Name+" "+pi.Constraint)
		}
		p("Products: %s\n\n", strings.Join(names, ", "))
	}

	var counts []string
	for _, c := range r.Counts {
		counts = append(counts, fmt.Sprintf("%s %d", c.Priority, c.Count))
	}
	p("Summary: %s | not relevant %d | below threshold %d | already reported %d | still open %d",
		strings.Join(counts, " · "), r.NotRelevant, r.BelowThreshold, r.Unchanged, len(r.Open))
	if r.ImageFiltered > 0 {
		p(" | image findings filtered %d", r.ImageFiltered)
	}
	if r.KernelFiltered > 0 {
		p(" | kernel fixes filtered %d", r.KernelFiltered)
	}
	p("\n")

	if r.Empty() {
		p("\n%s\n", o.c(bold, "No new findings."))
	}
	if len(r.Baselines) > 0 {
		found, clean := r.BaselineSplit()
		p("\n%s\n", o.c(bold, fmt.Sprintf("== Full history checked · %d products ==", len(r.Baselines))))
		p("%s\n", o.c(dim, "New products and changed versions are checked against every known advisory; what affects us is listed under Still open."))
		for _, b := range found {
			p("  %s %s %s  %s\n", o.c(bold, report.Named(b.Scope, b.Product)), b.Constraint, o.c(dim, "("+b.Reason+")"), b.Facts())
		}
		if len(clean) > 0 {
			p("  %s\n", o.c(dim, fmt.Sprintf("+ %d with nothing affecting the deployed version: %s", len(clean), report.Names(clean))))
		}
	}
	for _, g := range r.Groups {
		p("\n%s\n", o.c(prioColor[g.Priority], fmt.Sprintf("== %s · %s ==", g.Priority, g.Label)))
		for _, pg := range g.Products {
			p("\n  %s %s\n", o.c(bold, report.Named(pg.Scope, pg.Product)), o.c(dim, "(we run "+pg.Constraint+")"))
			for _, it := range pg.Items {
				o.item(&b, it)
			}
		}
	}
	if len(r.Open) > 0 || r.OpenUnknown > 0 {
		p("\n%s\n", o.c(bold, fmt.Sprintf("== Still open · %d ==", len(r.Open))))
		if len(r.Open) > 0 {
			p("%s\n", o.c(dim, "Reported earlier and still affecting the versions in stack.yaml."))
		}
		for _, it := range r.Open {
			o.openItem(&b, it)
		}
		if r.OpenUnknown > 0 {
			p("  %s\n", o.c(dim, fmt.Sprintf("+ %d findings not listed: they give no affected versions, so vulnwatch can't tell whether ours is affected (or the product is tracked with \"*\").", r.OpenUnknown)))
		}
	}
	if len(r.UnmatchedImages) > 0 {
		p("\n%s\n", o.c(dim, fmt.Sprintf("Trivy scanned %d images that belong to no product in the stack (add them to the catalog with images:): %s",
			len(r.UnmatchedImages), report.UnmatchedLine(r.UnmatchedImages, 8))))
	}
	if len(r.Warnings) > 0 {
		p("\n%s\n", o.c(yellow+bold, "Warnings:"))
		for _, w := range r.Warnings {
			p("  ! %s\n", w)
		}
	}
	return b.String()
}

func (o *Output) item(b *strings.Builder, it report.Item) {
	p := func(format string, a ...any) { fmt.Fprintf(b, format, a...) }
	head := []string{o.c(bold, it.ID)}
	if it.CVSS > 0 {
		head = append(head, fmt.Sprintf("CVSS %.1f", it.CVSS))
	}
	head = append(head, it.Severity)
	if it.KEV {
		head = append(head, o.c(red+bold, "[KEV]"))
	}
	if it.PublicExploit {
		head = append(head, o.c(red+bold, "[EXPLOIT]"))
	}
	if it.EPSS > 0 {
		head = append(head, fmt.Sprintf("[EPSS %.1f%%]", it.EPSS*100))
	}
	head = append(head, "match: "+it.Match)
	switch {
	case it.ImageOnly:
		head = append(head, o.c(cyan, "[image only]"))
	case len(it.Packages) > 0:
		head = append(head, o.c(cyan, "[confirmed in image]"))
	}
	if it.Change != "new" {
		head = append(head, o.c(cyan, "updated"))
	}
	p("    %s\n", strings.Join(head, "  "))
	if it.Change != "new" {
		p("      Changed: %s\n", it.Change)
	}
	if len(it.Fixed) > 0 {
		p("      Fixed in: %s\n", strings.Join(it.Fixed, ", "))
	}
	if len(it.Packages) > 0 {
		p("      In images: %s\n", report.PackageLine(it.Packages, 3))
	}
	if it.Title != "" && it.Title != it.Summary {
		p("      %s\n", o.c(bold, it.Title))
	}
	p("      %s\n", it.Summary)
	p("      Action: %s\n", it.Action)
	if !it.Triaged {
		p("      %s\n", o.c(dim, "("+it.TriageNote+")"))
	}
	if len(it.Advisories) > 0 {
		p("      %s\n", report.AdvisoryLine(it.Advisories))
	}
	for _, l := range it.Links {
		p("      %s\n", o.c(dim, l))
	}
}

func (o *Output) openItem(b *strings.Builder, it report.OpenItem) {
	parts := []string{o.c(prioColor[it.Priority], it.Priority), report.Named(it.Scope, it.Product) + " " + it.Constraint, o.c(bold, it.ID), it.Severity}
	if it.CVSS > 0 {
		parts[len(parts)-1] += fmt.Sprintf(" %.1f", it.CVSS)
	}
	if it.KEV {
		parts = append(parts, o.c(red+bold, "[KEV]"))
	}
	if it.PublicExploit {
		parts = append(parts, o.c(red+bold, "[EXPLOIT]"))
	}
	if len(it.Fixed) > 0 {
		parts = append(parts, "fixed in "+strings.Join(it.Fixed, ", "))
	}
	parts = append(parts, fmt.Sprintf("open %dd", it.DaysOpen))
	switch {
	case it.ImageOnly:
		parts = append(parts, o.c(cyan, "[image only]"))
	case it.NoVersionData:
		parts = append(parts, o.c(dim, "(no version data; clears when you upgrade)"))
	case it.Match != "affected":
		parts = append(parts, o.c(dim, "(depends on exact version)"))
	}
	fmt.Fprintf(b, "  %s\n", strings.Join(parts, "  "))
	if len(it.Packages) > 0 {
		fmt.Fprintf(b, "      %s\n", o.c(dim, "In images: "+report.PackageLine(it.Packages, 2)))
	}
	if len(it.Advisories) > 0 {
		fmt.Fprintf(b, "      %s\n", o.c(dim, report.AdvisoryLine(it.Advisories)))
	}
}
