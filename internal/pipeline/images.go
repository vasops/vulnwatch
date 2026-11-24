package pipeline

import (
	"fmt"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/sources"
)

// imageSource is a source whose findings come from scanned images (trivy).
type imageSource interface {
	UnmatchedImages() []string
}

// imageState is what this run learned from the image source.
type imageState struct {
	ok        bool            // the source ran and every product answered
	seen      map[string]bool // product/ID of every image finding now, before filtering
	unmatched []string
	filtered  int
}

func newImageState(srcs []sources.Source, warnings []string) imageState {
	st := imageState{seen: map[string]bool{}}
	for _, s := range srcs {
		is, ok := s.(imageSource)
		if !ok {
			continue
		}
		st.ok = !slices.ContainsFunc(warnings, func(w string) bool { return strings.HasPrefix(w, s.Name()+"/") })
		st.unmatched = is.UnmatchedImages()
	}
	return st
}

// note records the image findings seen in this run.
func (st *imageState) note(fs []finding.Finding) {
	for _, f := range fs {
		if f.InImage() {
			for _, id := range f.IDs() {
				st.seen[f.Product+"/"+id] = true
			}
		}
	}
}

// stillRunning reports whether an earlier image-only finding is still in a
// running image; ok is false when the image source didn't answer.
func (st imageState) stillRunning(product, id string) (running, ok bool) {
	return st.seen[product+"/"+id], st.ok
}

// dropUnfixedImageOnly removes image-only findings without a fixed package
// before enrichment: they are never reported, and there are many.
func (st *imageState) dropUnfixedImageOnly(fs []finding.Finding) []finding.Finding {
	return slices.DeleteFunc(fs, func(f finding.Finding) bool {
		if f.ImageOnly() && !hasFixedPackage(f) {
			st.filtered++
			return true
		}
		return false
	})
}

// filterImageOnly keeps the image-only findings worth reporting (see
// config.TrivySource); findings with an advisory are always kept.
func (st *imageState) filterImageOnly(fs []finding.Finding, byName map[string]catalog.Product, cfg config.TrivySource) []finding.Finding {
	return slices.DeleteFunc(fs, func(f finding.Finding) bool {
		if !f.ImageOnly() || keepImageFinding(f, byName[f.Product], cfg) {
			return false
		}
		st.filtered++
		return true
	})
}

func keepImageFinding(f finding.Finding, p catalog.Product, cfg config.TrivySource) bool {
	if !hasFixedPackage(f) {
		return false
	}
	if f.KEV || f.PublicExploit || (cfg.MinEPSS > 0 && f.EPSS >= cfg.MinEPSS) {
		return true
	}
	min := cfg.MinSeverity
	if p.Exposure == "internet" {
		min = cfg.MinSeverityInternet
	}
	return finding.SeverityRank(f.Severity) >= finding.SeverityRank(min)
}

func hasFixedPackage(f finding.Finding) bool {
	return slices.ContainsFunc(f.Packages, func(p finding.Package) bool { return p.Fixed != "" })
}

// imageDetail describes the image evidence for the match detail.
func imageDetail(f finding.Finding) string {
	s := "Trivy found " + f.Packages[0].String()
	if n := len(f.Packages) - 1; n > 0 {
		s += fmt.Sprintf(" and %d more", n)
	}
	return s
}
