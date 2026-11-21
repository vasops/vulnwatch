package brand

import (
	"strings"
	"testing"
)

func TestBannerPlainAndColor(t *testing.T) {
	plain := Banner(false, "v1.2.3")
	if strings.Contains(plain, "\x1b[") {
		t.Fatal("escape codes without color")
	}
	for _, want := range []string{"vulnwatch", tagline, "v1.2.3", "●", "╱"} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q in\n%s", want, plain)
		}
	}
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 lines, got %d", len(lines))
	}
	color := Banner(true, "")
	if !strings.Contains(color, "\x1b[1m\x1b[38;2;255;181;71m●") || !strings.Contains(color, "38;2;91;227;138") {
		t.Fatalf("blip amber / ring phosphor missing:\n%q", color)
	}
}
