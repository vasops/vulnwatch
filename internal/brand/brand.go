// Package brand renders the vulnwatch logo for the terminal: a radar sweep
// with one amber blip (see logo/). Colors are 24-bit ANSI; without color the
// same shapes print plain.
package brand

import (
	"fmt"
	"strconv"
	"strings"
)

// Colors from logo/README.md.
const (
	Phosphor = "#5BE38A" // mark on dark
	Blip     = "#FFB547" // the finding
	Mist     = "#DFF5E6" // wordmark on dark
)

const tagline = "the daily sweep for vulnerabilities in what you run"

type painter bool

func (p painter) paint(hex string, bold bool, s string) string {
	if !p {
		return s
	}
	rgb, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	code := fmt.Sprintf("\x1b[38;2;%d;%d;%dm", rgb>>16, rgb>>8&0xff, rgb&0xff)
	if bold {
		code = "\x1b[1m" + code
	}
	return code + s + "\x1b[0m"
}

func (p painter) dim(s string) string {
	if !p {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

// Mark returns the radar: ring, sweep from the centre up and to the right,
// and the blip below right of the centre (logo/mark-dark.svg).
func Mark(color bool) string {
	p := painter(color)
	ring := func(s string) string { return p.paint(Phosphor, false, s) }
	sweep := p.paint(Phosphor, true, "╱")
	center := p.paint(Phosphor, true, "•")
	blip := p.paint(Blip, true, "●")
	return strings.Join([]string{
		ring("  ╭─────╮  "),
		ring(" ╱   ") + sweep + ring("   ╲ "),
		ring("│   ") + center + ring("     │"),
		ring(" ╲     ") + blip + ring(" ╱ "),
		ring("  ╰─────╯  "),
	}, "\n")
}

// Wordmark returns "vulnwatch" in the logo's wordmark color.
func Wordmark(color bool) string {
	return painter(color).paint(Mist, true, "vulnwatch")
}

// Banner returns the splash: the mark beside the wordmark, the tagline and
// an optional detail line (e.g. the version).
func Banner(color bool, detail string) string {
	p := painter(color)
	text := []string{"", Wordmark(color), p.dim(tagline), p.dim(detail), ""}
	mark := strings.Split(Mark(color), "\n")
	var b strings.Builder
	for i, m := range mark {
		b.WriteString(m)
		if i < len(text) && text[i] != "" {
			b.WriteString("   " + text[i])
		}
		b.WriteString("\n")
	}
	return b.String()
}
