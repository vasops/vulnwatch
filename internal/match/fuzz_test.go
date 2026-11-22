package match

import (
	"testing"

	"github.com/vasops/vulnwatch/internal/finding"
)

// Constraints and ranges come from stack.yaml, Helm charts and advisories.
func FuzzMatch(f *testing.F) {
	for _, s := range []string{"26.7.0", "26.x", ">=10.4 <11", "20.0.3 || 26.7.0", "*", "v1.30.4+rke2r1", "RELEASE.2025-04-22T22-12-26Z", "1.8", "0:5.14.0-427.el9_4", "", "|| ||", ">=<1"} {
		f.Add(s, "26.0.0", "26.1.4")
	}
	f.Fuzz(func(t *testing.T, constraint, introduced, fixed string) {
		c, err := ParseConstraint(constraint)
		if err != nil {
			return
		}
		if _, err := ParseConstraint(c.String()); err != nil {
			t.Fatalf("%q parsed, but its String %q doesn't: %v", constraint, c.String(), err)
		}
		Match(c, []finding.Range{{Introduced: introduced, Fixed: fixed}}, []string{introduced})
		Union(constraint, fixed)
		_, _ = ParseVersion(fixed)
	})
}
