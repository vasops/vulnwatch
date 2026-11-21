package textx

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncate(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"short", 0, "short"},
		{"fixed version released 1.7.29", 30, "fixed version released 1.7.29"},
		{"fixed version released 1.7.29", 20, "fixed version…"},
		{"fixed version, released", 15, "fixed version…"},
		{"word boundary", 6, "word…"},
		{strings.Repeat("a", 20), 10, strings.Repeat("a", 9) + "…"},
		{"a verylongtokenwithoutspaces", 10, "a verylon…"},
		{"ünïcödé wörds hère", 12, "ünïcödé…"},
	} {
		got := Truncate(tc.in, tc.n)
		if got != tc.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
		if tc.n > 0 && utf8.RuneCountInString(got) > tc.n {
			t.Errorf("Truncate(%q, %d) = %q: too long", tc.in, tc.n, got)
		}
	}
}
