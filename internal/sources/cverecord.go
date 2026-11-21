package sources

import (
	"strings"

	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/match"
)

// CNAVersion converts one entry of a CVE record's affected versions list
// (CVE JSON 5, as the CNA wrote it; NVD passes it on) into a range or a
// single affected version: version up to lessThan (exclusive) or
// lessThanOrEqual, a range expression in the version string (GitHub as
// CNA: ">= 1.2.0, < 1.2.5"), or one version. A start that names no version
// ("0", "*", "n/a") means from the beginning, an upper bound "*" no upper
// bound. ok is false for git commits and for entries that name no version.
// Range bounds are not parsed here: one that doesn't parse makes the match
// unknown.
func CNAVersion(version, lessThan, lessThanOrEqual, versionType string) (r finding.Range, exact string, ok bool) {
	if strings.EqualFold(versionType, "git") {
		return r, "", false
	}
	switch {
	case lessThan != "":
		return finding.Range{Introduced: zeroToEmpty(version), Fixed: openEnd(lessThan)}, "", true
	case lessThanOrEqual != "":
		return finding.Range{Introduced: zeroToEmpty(version), LastAffected: openEnd(lessThanOrEqual)}, "", true
	case strings.ContainsAny(version, "<>"):
		r, err := match.ParseRangeExpr(version)
		if err != nil {
			return r, "", false
		}
		r.Introduced = zeroToEmpty(r.Introduced)
		return r, "", true
	case isVersion(version):
		return r, version, true
	}
	return r, "", false
}

// placeholder reports whether a CNA version field names no version.
func placeholder(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "n/a", "unspecified", "-", "*":
		return true
	}
	return false
}

// isVersion reports whether a CNA version field is a single version that
// can be matched: no placeholder, nothing ParseVersion rejects.
func isVersion(v string) bool {
	if placeholder(v) {
		return false
	}
	_, err := match.ParseVersion(v)
	return err == nil
}

// zeroToEmpty maps a range start that names no version ("0", "n/a",
// "unspecified", "-", "*") to "", the beginning.
func zeroToEmpty(v string) string {
	if placeholder(v) {
		return ""
	}
	return v
}

// openEnd maps the upper bound "*" (every later version) to "", no bound.
func openEnd(v string) string {
	if strings.TrimSpace(v) == "*" {
		return ""
	}
	return v
}

// CPEMatches compares a catalog CPE match string (nvd:, often a prefix such
// as "cpe:2.3:a:grafana:grafana") with a CPE 2.3 string component by
// component; "*" or a missing component in the selector matches anything.
func CPEMatches(selector, cpe string) bool {
	sp, cp := strings.Split(selector, ":"), strings.Split(cpe, ":")
	for i, s := range sp {
		if s == "*" || s == "" {
			continue
		}
		if i >= len(cp) || !strings.EqualFold(s, cp[i]) {
			return false
		}
	}
	return true
}
