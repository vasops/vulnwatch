package finding

// Range is one affected version range, normalized across sources.
// Empty Introduced means "from the beginning"; empty Fixed and LastAffected
// means "no upper bound".
type Range struct {
	Introduced          string `json:"introduced,omitempty"`
	IntroducedExclusive bool   `json:"introduced_exclusive,omitempty"`
	Fixed               string `json:"fixed,omitempty"`         // exclusive upper bound
	LastAffected        string `json:"last_affected,omitempty"` // inclusive upper bound
	// Platform limits the range to a platform the product runs on ("windows"):
	// NVD configurations that combine the product with a non-vulnerable one.
	Platform string `json:"platform,omitempty"`
	// Exact marks one listed affected version (Introduced == LastAffected),
	// matched like an entry of a version list, not like a range.
	Exact bool `json:"exact,omitempty"`
	// Source is the source that reported the range (see TagSource); empty
	// in findings recorded before ranges were tagged.
	Source string `json:"source,omitempty"`
}

// AllVersions reports whether the range has no bounds at all, which sources
// use for "not specified".
func (r Range) AllVersions() bool {
	r.Source = ""
	return r == Range{}
}

// String renders the range as a constraint expression; an exact version as
// itself.
func (r Range) String() string {
	if r.Exact {
		return r.Introduced
	}
	var s string
	if r.Introduced != "" && r.Introduced != "0" {
		op := ">="
		if r.IntroducedExclusive {
			op = ">"
		}
		s = op + r.Introduced
	}
	add := func(part string) {
		if s != "" {
			s += " "
		}
		s += part
	}
	switch {
	case r.Fixed != "":
		add("<" + r.Fixed)
	case r.LastAffected != "":
		add("<=" + r.LastAffected)
	}
	if s == "" {
		return "*"
	}
	return s
}
