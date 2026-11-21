// Package textx holds small text helpers shared by sources and outputs.
package textx

import (
	"strings"
	"unicode"
)

// Truncate shortens s to at most n runes, the ellipsis included. It cuts at
// a word boundary when there is one in the second half of the kept text,
// else mid-word (one long token, e.g. a URL).
func Truncate(s string, n int) string {
	r := []rune(s)
	if n <= 0 || len(r) <= n {
		return s
	}
	keep := r[:n-1]
	if !unicode.IsSpace(r[n-1]) {
		if i := lastSpace(keep); i > len(keep)/2 {
			keep = keep[:i]
		}
	}
	return strings.TrimRight(string(keep), " \t\r\n.,;:") + "…"
}

func lastSpace(r []rune) int {
	for i := len(r) - 1; i >= 0; i-- {
		if unicode.IsSpace(r[i]) {
			return i
		}
	}
	return -1
}
