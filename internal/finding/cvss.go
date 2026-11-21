package finding

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

var cvssVectorRe = regexp.MustCompile(`CVSS:3\.[01]/[A-Z:/]+`)

// FindCVSS3Vector returns the first CVSS v3.x vector found in text.
func FindCVSS3Vector(text string) string {
	return cvssVectorRe.FindString(text)
}

// CVSS3Score computes the CVSS v3.0/v3.1 base score from a vector string.
// It returns 0 and an error for anything that is not a complete v3 vector
// (CVSS v4 scores need the full macro-vector tables and are not computed).
func CVSS3Score(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 || (parts[0] != "CVSS:3.1" && parts[0] != "CVSS:3.0") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("bad CVSS metric %q", p)
		}
		m[k] = v
	}
	scope := m["S"]
	lookup := func(metric string, table map[string]float64) (float64, error) {
		v, ok := table[m[metric]]
		if !ok {
			return 0, fmt.Errorf("CVSS metric %s missing or invalid in %q", metric, vector)
		}
		return v, nil
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	} else if scope != "U" {
		return 0, fmt.Errorf("CVSS scope missing in %q", vector)
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	var (
		vals [7]float64
		err  error
	)
	specs := []struct {
		metric string
		table  map[string]float64
	}{
		{"AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}},
		{"AC", map[string]float64{"L": 0.77, "H": 0.44}},
		{"PR", prTable},
		{"UI", map[string]float64{"N": 0.85, "R": 0.62}},
		{"C", cia}, {"I", cia}, {"A", cia},
	}
	for i, s := range specs {
		if vals[i], err = lookup(s.metric, s.table); err != nil {
			return 0, err
		}
	}
	av, ac, pr, ui, c, in, a := vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6]
	iss := 1 - (1-c)*(1-in)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	expl := 8.22 * av * ac * pr * ui
	if scope == "U" {
		return roundUp(math.Min(impact+expl, 10)), nil
	}
	return roundUp(math.Min(1.08*(impact+expl), 10)), nil
}

// roundUp implements the CVSS v3.1 Roundup function.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
