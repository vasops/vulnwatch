package news

import (
	"regexp"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
)

// Hit is a stack product a headline names, with where it runs.
type Hit struct {
	Product string
	Scopes  []config.Scope // where it runs, by tenant and environment
}

// Matcher finds the stack's products in headlines by catalog name and
// alias, as whole words, case-insensitively. Names shorter than three
// letters ("go") are left out: as words they match too much. The nodes'
// kernel is found by "kernel".
type Matcher struct {
	products []string                  // sorted
	terms    map[string][]string       // product -> terms
	scopes   map[string][]config.Scope // product -> scopes, sorted
	re       map[string]*regexp.Regexp
}

const minTermLen = 3

// NewMatcher indexes the products of every scope.
func NewMatcher(products []catalog.Product) *Matcher {
	m := &Matcher{terms: map[string][]string{}, scopes: map[string][]config.Scope{}, re: map[string]*regexp.Regexp{}}
	for _, p := range products {
		if _, ok := m.terms[p.Name]; !ok {
			m.products = append(m.products, p.Name)
			m.terms[p.Name] = productTerms(p)
		}
		if !slices.ContainsFunc(m.scopes[p.Name], func(s config.Scope) bool { return s.String() == p.Scope.String() }) {
			m.scopes[p.Name] = append(m.scopes[p.Name], p.Scope)
		}
	}
	slices.Sort(m.products)
	for _, name := range m.products {
		slices.SortFunc(m.scopes[name], func(a, b config.Scope) int { return strings.Compare(a.String(), b.String()) })
		var alts []string
		for _, t := range m.terms[name] {
			alts = append(alts, regexp.QuoteMeta(t))
		}
		if len(alts) > 0 {
			m.re[name] = regexp.MustCompile(`(?i)(?:^|[^\pL\pN])(?:` + strings.Join(alts, "|") + `)(?:$|[^\pL\pN])`)
		}
	}
	return m
}

func productTerms(p catalog.Product) []string {
	if p.OS != nil {
		return []string{"kernel"}
	}
	var out []string
	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if len([]rune(t)) >= minTermLen && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for _, n := range append([]string{p.Name}, p.Entry.Aliases...) {
		add(n)
		add(strings.ReplaceAll(n, "-", " ")) // gitlab-ce: "GitLab CE"
	}
	return out
}

// Match returns the products the text names, by product name.
func (m *Matcher) Match(text string) []Hit {
	var out []Hit
	for _, name := range m.products {
		if re := m.re[name]; re != nil && re.MatchString(text) {
			out = append(out, Hit{Product: name, Scopes: m.scopes[name]})
		}
	}
	return out
}
