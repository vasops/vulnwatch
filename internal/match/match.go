// Package match parses version constraints and deterministically matches
// them against the affected ranges of a finding.
package match

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/go-version"

	"github.com/vasops/vulnwatch/internal/finding"
)

// Status is the deterministic version-match result.
type Status string

const (
	Affected    Status = "affected"
	NotAffected Status = "not_affected"
	Unknown     Status = "unknown"
)

// ParseVersion parses a version, tolerating common non-semver tags such as
// "v1.30.4+rke2r1", "release-1.2.3", Maven's "26.0.6.Final" or MinIO's
// "RELEASE.2025-04-22T22-12-26Z" (compared as 2025.4.22.221226).
func ParseVersion(s string) (*version.Version, error) {
	n := strings.TrimSpace(s)
	if m := minioRelease.FindStringSubmatch(n); m != nil {
		segs := make([]string, 4)
		for i, d := range []string{m[1], m[2], m[3], strings.ReplaceAll(m[4], "-", "")} {
			segs[i] = strings.TrimLeft(d, "0")
			if segs[i] == "" {
				segs[i] = "0"
			}
		}
		n = strings.Join(segs, ".")
	}
	if dateOnly.MatchString(n) {
		return nil, fmt.Errorf("%q is a date, not a version", s)
	}
	n = javaUpdate.ReplaceAllString(n, "$1.$2")
	n = strings.TrimPrefix(n, "release-")
	n = strings.TrimLeft(n, "vV")
	n = mavenQualifier.ReplaceAllStringFunc(n, func(q string) string {
		switch strings.ToLower(q[1:]) {
		case "final", "ga", "release":
			return ""
		}
		return "-" + q[1:]
	})
	v, err := version.NewVersion(n)
	if err != nil {
		return nil, fmt.Errorf("unparseable version %q", s)
	}
	return v, nil
}

// minioRelease matches MinIO's date-based release tags; NVD spells them
// lower-case without the prefix ("2025-04-22t22-12-26z").
var minioRelease = regexp.MustCompile(`(?i)^(?:RELEASE\.)?(\d{4})-(\d{2})-(\d{2})T(\d{2}-\d{2}-\d{2})Z$`)

// dateOnly matches a bare date, which NVD sometimes gives as a bound for
// products without releases it tracks ("LiteLLM through 2026-04-08"). Read
// as a version it is 2026.4.8, above every semantic version: the range
// would cover any release, so it is left unparseable (Unknown).
var dateOnly = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// javaUpdate matches Java's legacy update numbering, which NVD keeps in old
// Oracle JDK/JRE records ("1.4.2_37" = 1.4.2 update 37).
var javaUpdate = regexp.MustCompile(`^(\d+\.\d+\.\d+)_(\d+)$`)

// mavenQualifier matches a dotted alphabetic qualifier at the end ("26.0.6.Final").
var mavenQualifier = regexp.MustCompile(`\.[A-Za-z][A-Za-z0-9]*$`)

// cmpVer compares versions; when the cores are equal and both carry build
// metadata (RKE2's "+rke2r1" vs "+rke2r2"), metadata breaks the tie in
// natural order. Semver itself ignores metadata.
func cmpVer(a, b *version.Version) int {
	if c := a.Compare(b); c != 0 {
		return c
	}
	am, bm := a.Metadata(), b.Metadata()
	if am == "" || bm == "" {
		return 0
	}
	return naturalCompare(am, bm)
}

var digitRun = regexp.MustCompile(`\d+|\D+`)

func naturalCompare(a, b string) int {
	ap, bp := digitRun.FindAllString(a, -1), digitRun.FindAllString(b, -1)
	for i := 0; i < len(ap) && i < len(bp); i++ {
		an, aerr := strconv.Atoi(ap[i])
		bn, berr := strconv.Atoi(bp[i])
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				return cmp.Compare(an, bn)
			}
		case ap[i] != bp[i]:
			return strings.Compare(ap[i], bp[i])
		}
	}
	return cmp.Compare(len(ap), len(bp))
}

type bound struct {
	v    *version.Version // nil = unbounded
	incl bool
}

type interval struct{ lo, hi bound }

func (i interval) isPoint() bool {
	return i.lo.v != nil && i.hi.v != nil && i.lo.incl && i.hi.incl && cmpVer(i.lo.v, i.hi.v) == 0
}

// lowerLE reports whether lower bound a is at or below lower bound b.
func lowerLE(a, b bound) bool {
	if a.v == nil {
		return true
	}
	if b.v == nil {
		return false
	}
	if c := cmpVer(a.v, b.v); c != 0 {
		return c < 0
	}
	return a.incl || !b.incl
}

// upperGE reports whether upper bound a is at or above upper bound b.
func upperGE(a, b bound) bool {
	if a.v == nil {
		return true
	}
	if b.v == nil {
		return false
	}
	if c := cmpVer(a.v, b.v); c != 0 {
		return c > 0
	}
	return a.incl || !b.incl
}

func contains(outer, inner interval) bool {
	return lowerLE(outer.lo, inner.lo) && upperGE(outer.hi, inner.hi)
}

func overlaps(a, b interval) bool {
	lo := a.lo
	if lowerLE(a.lo, b.lo) {
		lo = b.lo
	}
	hi := a.hi
	if upperGE(a.hi, b.hi) {
		hi = b.hi
	}
	if lo.v == nil || hi.v == nil {
		return true
	}
	if c := cmpVer(lo.v, hi.v); c != 0 {
		return c < 0
	}
	return lo.incl && hi.incl
}

// Constraint is a parsed stack.yaml version constraint. A union
// ("13.0.5 || 13.2.4", one product deployed in several versions) keeps one
// constraint per alternative in alts.
type Constraint struct {
	raw  string
	any  bool
	iv   interval
	alts []Constraint
}

func (c Constraint) String() string { return c.raw }

// Alternatives returns the parts of a union ("13.0.5 || 13.2.4"), or the
// constraint itself.
func (c Constraint) Alternatives() []Constraint {
	if len(c.alts) > 0 {
		return c.alts
	}
	return []Constraint{c}
}

// Any reports whether the constraint tracks all versions ("*").
func (c Constraint) Any() bool { return c.any }

var opSpace = regexp.MustCompile(`(>=|<=|==|!=|>|<|=)\s+`)

// ParseConstraint parses exact versions ("1.8.1"), wildcards ("26.x",
// "26.1.x"), ranges (">=10.4 <11", comma or space separated), "*" and unions
// of those separated by "||". A partial version without wildcard ("1.8") is
// treated as "1.8.x".
func ParseConstraint(s string) (Constraint, error) {
	raw := strings.TrimSpace(s)
	parts := strings.Split(raw, "||")
	if len(parts) == 1 {
		return parseSingle(raw)
	}
	c := Constraint{raw: raw}
	for _, p := range parts {
		alt, err := parseSingle(strings.TrimSpace(p))
		if err != nil {
			return c, err
		}
		if strings.TrimSpace(p) == "" {
			return c, fmt.Errorf("constraint %q: empty alternative", raw)
		}
		if alt.any {
			return Constraint{raw: raw, any: true}, nil
		}
		c.alts = append(c.alts, alt)
	}
	return c, nil
}

// Union joins constraints into one "a || b" constraint string, skipping
// duplicates and empty ones.
func Union(cs ...string) string {
	var out []string
	for _, c := range cs {
		for _, p := range strings.Split(c, "||") {
			if p = strings.TrimSpace(p); p != "" && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return strings.Join(out, " || ")
}

func parseSingle(raw string) (Constraint, error) {
	c := Constraint{raw: raw}
	if raw == "" || raw == "*" || raw == "x" {
		c.any = true
		return c, nil
	}
	norm := opSpace.ReplaceAllString(raw, "$1")
	tokens := strings.FieldsFunc(norm, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' })
	if len(tokens) == 1 && !strings.ContainsAny(tokens[0], "<>=!") {
		iv, err := parseBare(tokens[0])
		if err != nil {
			return c, fmt.Errorf("constraint %q: %w", raw, err)
		}
		c.iv = iv
		return c, nil
	}
	iv := interval{}
	for _, t := range tokens {
		op, ver := splitOp(t)
		if op == "" {
			return c, fmt.Errorf("constraint %q: %q needs an operator (>=, >, <=, <, =) when combined", raw, t)
		}
		if op == "!=" {
			return c, fmt.Errorf("constraint %q: != is not supported", raw)
		}
		v, err := ParseVersion(ver)
		if err != nil {
			return c, fmt.Errorf("constraint %q: %w", raw, err)
		}
		switch op {
		case ">=", ">":
			b := bound{v: v, incl: op == ">="}
			if iv.lo.v != nil && lowerLE(b, iv.lo) {
				continue // keep the tighter existing bound
			}
			iv.lo = b
		case "<=", "<":
			b := bound{v: v, incl: op == "<="}
			if iv.hi.v != nil && upperGE(b, iv.hi) {
				continue
			}
			iv.hi = b
		case "=", "==":
			iv.lo, iv.hi = bound{v, true}, bound{v, true}
		}
	}
	if iv.lo.v != nil && iv.hi.v != nil && !overlaps(iv, iv) {
		return c, fmt.Errorf("constraint %q matches no version", raw)
	}
	c.iv = iv
	return c, nil
}

func splitOp(t string) (op, ver string) {
	for _, o := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
		if rest, ok := strings.CutPrefix(t, o); ok {
			return o, rest
		}
	}
	return "", t
}

// parseBare handles a single operator-less token: exact, partial or wildcard.
func parseBare(t string) (interval, error) {
	t = strings.TrimLeft(t, "vV")
	parts := strings.Split(t, ".")
	wild := false
	if last := parts[len(parts)-1]; last == "x" || last == "X" || last == "*" {
		wild = true
		parts = parts[:len(parts)-1]
	}
	allNumeric := true
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			allNumeric = false
		}
	}
	if !wild && (!allNumeric || len(parts) >= 3) {
		v, err := ParseVersion(t)
		if err != nil {
			return interval{}, err
		}
		return interval{bound{v, true}, bound{v, true}}, nil
	}
	if !allNumeric || len(parts) == 0 {
		return interval{}, fmt.Errorf("invalid wildcard %q", t)
	}
	lo, err := version.NewVersion(strings.Join(parts, "."))
	if err != nil {
		return interval{}, err
	}
	next := append([]string(nil), parts...)
	n, _ := strconv.Atoi(next[len(next)-1])
	next[len(next)-1] = strconv.Itoa(n + 1)
	hi, err := version.NewVersion(strings.Join(next, "."))
	if err != nil {
		return interval{}, err
	}
	return interval{bound{lo, true}, bound{hi, false}}, nil
}

func rangeInterval(r finding.Range) (interval, error) {
	var iv interval
	if r.Introduced != "" && r.Introduced != "0" {
		v, err := ParseVersion(r.Introduced)
		if err != nil {
			return iv, err
		}
		iv.lo = bound{v, !r.IntroducedExclusive}
	}
	switch {
	case r.Fixed != "":
		v, err := ParseVersion(r.Fixed)
		if err != nil {
			return iv, err
		}
		iv.hi = bound{v, false}
	case r.LastAffected != "":
		v, err := ParseVersion(r.LastAffected)
		if err != nil {
			return iv, err
		}
		iv.hi = bound{v, true}
	}
	return iv, nil
}

// Result is the outcome of matching one finding against one constraint.
type Result struct {
	Status Status
	Detail string // human-readable reason, also fed to triage
}

// Match compares a constraint with a finding's affected ranges and explicit
// affected versions. It never guesses: missing or partial data is Unknown.
//
//   - Affected: every version the constraint allows lies in an affected range.
//   - NotAffected: no allowed version is affected.
//   - Unknown: "*" constraint, no usable data, only partial overlap, or
//     affected only on a platform.
//
// Each source's data (Range.Source; versions and untagged ranges count as
// one source) is matched on its own: when every source with data agrees,
// that is the result, otherwise Unknown naming each source's verdict. A
// coarse range of one source can't override another's per-branch ranges.
func Match(c Constraint, ranges []finding.Range, versions []string) Result {
	if len(c.alts) > 0 {
		return matchUnion(c, ranges, versions)
	}
	if c.any {
		return Result{Unknown, "all versions tracked; version match left to triage"}
	}
	// Open-ended ranges are pruned across sources: the one with the fix in
	// another field is often next to another source's bounded ranges.
	groups := bySource(informative(ranges), versions)
	if len(groups) == 0 {
		return Result{Unknown, "source provides no affected version data"}
	}
	var (
		results   = make([]Result, len(groups))
		evidence  = make([]string, len(groups))
		disagreed bool
	)
	for i, g := range groups {
		results[i], evidence[i] = matchSource(c, g.ranges, g.versions)
		disagreed = disagreed || results[i].Status != results[0].Status
	}
	if !disagreed {
		return results[0]
	}
	parts := make([]string, len(groups))
	for i, g := range groups {
		parts[i] = fmt.Sprintf("%s: %s", cmp.Or(g.source, "unattributed"), strings.ReplaceAll(string(results[i].Status), "_", " "))
		if evidence[i] != "" {
			parts[i] += " (" + evidence[i] + ")"
		}
	}
	return Result{Unknown, "sources disagree: " + strings.Join(parts, "; ")}
}

// sourceData is the version data one source gave.
type sourceData struct {
	source   string
	ranges   []finding.Range
	versions []string
}

// bySource groups the version data by source, sorted by name; exact ranges
// go back to versions, untagged versions join the untagged ranges.
func bySource(ranges []finding.Range, versions []string) []sourceData {
	var out []sourceData
	group := func(src string) *sourceData {
		i := slices.IndexFunc(out, func(g sourceData) bool { return g.source == src })
		if i < 0 {
			out = append(out, sourceData{source: src})
			i = len(out) - 1
		}
		return &out[i]
	}
	for _, r := range ranges {
		g := group(r.Source)
		if r.Exact {
			g.versions = append(g.versions, r.Introduced)
			continue
		}
		g.ranges = append(g.ranges, r)
	}
	if len(versions) > 0 {
		g := group("")
		g.versions = append(g.versions, versions...)
	}
	slices.SortFunc(out, func(a, b sourceData) int { return strings.Compare(a.source, b.source) })
	return out
}

// matchSource matches the data of one source; ranges are informative and
// some data is given. Evidence is what the result rests on: the affected
// range or version, or why it is unknown.
func matchSource(c Constraint, ranges []finding.Range, versions []string) (res Result, evidence string) {
	// An unparseable range ("branch", "1.9.*") makes the result unknown
	// unless another range matched: it may be the one covering our version.
	// Unparseable version tags only do when nothing else could be parsed.
	// A range limited to a platform ("only on windows") is unknown as well.
	partial, platform, badRange, badVersions, parsed := "", "", "", 0, 0
	for _, r := range ranges {
		iv, err := rangeInterval(r)
		if err != nil {
			if badRange == "" {
				badRange = r.String()
			}
			continue
		}
		parsed++
		if contains(iv, c.iv) && r.Platform != "" {
			if platform == "" {
				platform = fmt.Sprintf("%s is within affected range %s, but only on %s; depends on the platform", c.raw, r, r.Platform)
			}
			continue
		}
		if contains(iv, c.iv) {
			return Result{Affected, fmt.Sprintf("%s is within affected range %s", c.raw, r)}, r.String()
		}
		if overlaps(iv, c.iv) && partial == "" {
			partial = r.String()
		}
	}
	for _, s := range versions {
		v, err := ParseVersion(s)
		if err != nil {
			badVersions++
			continue
		}
		parsed++
		p := interval{bound{v, true}, bound{v, true}}
		if contains(c.iv, p) {
			if c.iv.isPoint() {
				return Result{Affected, fmt.Sprintf("%s is listed as an affected version", s)}, s
			}
			if partial == "" {
				partial = s
			}
		}
	}
	switch {
	case platform != "":
		res = Result{Unknown, platform}
	case partial != "":
		res = Result{Unknown, fmt.Sprintf("%s partially overlaps affected %s; depends on the exact deployed version", c.raw, partial)}
	case badRange != "":
		res = Result{Unknown, fmt.Sprintf("affected range %s could not be parsed", badRange)}
	case badVersions > 0 && parsed == 0:
		res = Result{Unknown, "affected versions could not be parsed"}
	default:
		return Result{NotAffected, fmt.Sprintf("%s is outside all affected ranges", c.raw)}, ""
	}
	return res, res.Detail
}

// matchUnion: affected if any deployed version is, not affected only if none
// is, unknown otherwise.
func matchUnion(c Constraint, ranges []finding.Range, versions []string) Result {
	var unknown *Result
	for _, alt := range c.alts {
		r := Match(alt, ranges, versions)
		switch r.Status {
		case Affected:
			return r
		case Unknown:
			if unknown == nil {
				unknown = &r
			}
		}
	}
	if unknown != nil {
		return *unknown
	}
	return Result{NotAffected, fmt.Sprintf("%s: no deployed version is affected", c.raw)}
}

// informative keeps the ranges that say something. Sources merged into one
// finding often disagree: one gives the real per-branch ranges, another an
// open-ended one (">= 1.28.0" with the fix in a separate field, the Go
// vulnerability database unable to express v2+ fixes, NVD "all versions").
// So an open-ended range is dropped when a bounded range starts at the same
// version or covers its start; one starting elsewhere (OSV's "< 1.5.0,
// >= 2.0.0": 2.x is not fixed yet) stays. "All versions" is no data at all.
// Exact versions are kept as they are.
func informative(ranges []finding.Range) []finding.Range {
	var bounded, exact, open []finding.Range
	for _, r := range ranges {
		switch {
		case r.AllVersions():
		case r.Exact:
			exact = append(exact, r)
		case r.Fixed != "" || r.LastAffected != "":
			bounded = append(bounded, r)
		default:
			open = append(open, r)
		}
	}
	out := slices.Concat(bounded, exact)
	for _, o := range open {
		if !superseded(o, bounded) {
			out = append(out, o)
		}
	}
	return out
}

// superseded reports whether a bounded range starts where the open range o
// does, or covers its start.
func superseded(o finding.Range, bounded []finding.Range) bool {
	oiv, err := rangeInterval(o)
	if err != nil {
		return false
	}
	for _, b := range bounded {
		if b.Introduced == o.Introduced && b.IntroducedExclusive == o.IntroducedExclusive {
			return true
		}
		biv, err := rangeInterval(b)
		switch {
		case err != nil:
		case oiv.lo.v == nil:
			if biv.lo.v == nil {
				return true
			}
		case contains(biv, interval{oiv.lo, bound{oiv.lo.v, true}}):
			return true
		}
	}
	return false
}

// ParseRangeExpr parses a GHSA-style range expression such as
// ">= 1.0.0, < 1.2.3", "<= 2.0" or "= 1.4.1" into a Range.
func ParseRangeExpr(expr string) (finding.Range, error) {
	var r finding.Range
	norm := opSpace.ReplaceAllString(strings.TrimSpace(expr), "$1")
	for _, t := range strings.FieldsFunc(norm, func(c rune) bool { return c == ' ' || c == ',' }) {
		op, ver := splitOp(t)
		switch op {
		case ">=":
			r.Introduced = ver
		case ">":
			r.Introduced, r.IntroducedExclusive = ver, true
		case "<":
			r.Fixed = ver
		case "<=":
			r.LastAffected = ver
		case "=", "==", "":
			r.Introduced, r.LastAffected = ver, ver
		default:
			return r, fmt.Errorf("unsupported range expression %q", expr)
		}
	}
	return r, nil
}

// UpgradeTarget returns the lowest version that fixes every finding for a
// deployed version (alt, one part of a constraint). Each finding is given
// as its fixed versions; per finding the lowest fix above alt counts,
// releases before pre-releases. Findings without any fix are counted.
func UpgradeTarget(alt Constraint, fixes [][]string) (target string, unfixed int) {
	base := alt.iv.lo.v
	var best *version.Version
	for _, fs := range fixes {
		if len(fs) == 0 {
			unfixed++
			continue
		}
		var pick *version.Version
		var pickS string
		for _, f := range fs {
			v, err := ParseVersion(f)
			if err != nil || (base != nil && cmpVer(v, base) <= 0) {
				continue
			}
			better := pick == nil ||
				(pick.Prerelease() != "" && v.Prerelease() == "") ||
				((pick.Prerelease() == "") == (v.Prerelease() == "") && cmpVer(v, pick) < 0)
			if better {
				pick, pickS = v, f
			}
		}
		if pick != nil && (best == nil || cmpVer(pick, best) > 0) {
			best, target = pick, pickS
		}
	}
	return target, unfixed
}

// Allows reports whether the deployed version v satisfies the constraint
// (any alternative of a union). An unparseable version is not allowed.
func (c Constraint) Allows(v string) bool {
	if c.any {
		return true
	}
	if len(c.alts) > 0 {
		return slices.ContainsFunc(c.alts, func(a Constraint) bool { return a.Allows(v) })
	}
	pv, err := ParseVersion(v)
	if err != nil {
		return false
	}
	return contains(c.iv, interval{bound{pv, true}, bound{pv, true}})
}
