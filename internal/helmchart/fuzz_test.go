package helmchart

import (
	"bytes"
	"testing"
)

// Chart archives come from any repository listed in stack.yaml.
func FuzzParse(f *testing.F) {
	f.Add(tgz(f, map[string]string{"x/Chart.yaml": "name: x\nversion: 1.0.0\nappVersion: 2.0.0\n", "x/values.yaml": "image: {tag: v1}\n"}))
	f.Add(tgz(f, map[string]string{"x/Chart.yaml": "name: x\n", "x/charts/y/Chart.yaml": "name: y\n"}))
	f.Add([]byte{0x1f, 0x8b})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, archive []byte) {
		c, err := Parse(archive, 1<<20)
		if err == nil && c == nil {
			t.Fatal("nil chart without an error")
		}
	})
}

// Archives inside archives share one budget and a nesting limit.
func TestNestedArchiveLimits(t *testing.T) {
	inner := tgz(t, map[string]string{"z/Chart.yaml": "name: z\n", "z/values.yaml": "k: " + string(bytes.Repeat([]byte("a"), 600))})
	outer := tgz(t, map[string]string{"x/Chart.yaml": "name: x\n", "x/charts/z1.tgz": string(inner), "x/charts/z2.tgz": string(inner)})
	if _, err := Parse(outer, 1500+2*int64(len(inner))); err != nil {
		t.Fatalf("within the budget: %v", err)
	}
	// Each inner archive fits on its own, both together don't.
	if _, err := Parse(outer, 2*int64(len(inner))+700); err == nil {
		t.Fatal("nested archives must share the budget")
	}
	deep := tgz(t, map[string]string{"n/Chart.yaml": "name: n\n"})
	for i := range maxNesting + 1 {
		deep = tgz(t, map[string]string{"n/Chart.yaml": "name: n\n", "n/charts/c" + string(rune('a'+i)) + ".tgz": string(deep)})
	}
	if _, err := Parse(deep, 1<<20); err == nil {
		t.Fatal("nesting deeper than maxNesting must fail")
	}
}
