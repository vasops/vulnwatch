package pipeline

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/finding"
	"github.com/vasops/vulnwatch/internal/logx"
	"github.com/vasops/vulnwatch/internal/sources"
	"github.com/vasops/vulnwatch/internal/sources/nvd"
)

// sourceCVEList is the name of the cvelistV5 source.
const sourceCVEList = "cvelist"

// sourceCoverage counts the findings of full-history checks that only
// cvelistV5 or only NVD found, by source: once per product and ID however
// many tenants run the product, for products both cover (NVD CPEs, which
// cvelist matches too) and both answered for. It logs the counts and
// audits each such finding. Nil unless both sources run.
func sourceCoverage(ctx context.Context, log *slog.Logger, fs []finding.Finding, srcs []sources.Source, byName map[string]catalog.Product, warnings []string) map[string]int {
	compared := []string{sourceCVEList, nvd.Name}
	for _, name := range compared {
		if !slices.ContainsFunc(srcs, func(s sources.Source) bool { return s.Name() == name }) {
			return nil
		}
	}
	failed := map[string]bool{} // "<source>/<product>", see Collect
	for _, w := range warnings {
		k, _, _ := strings.Cut(w, ":")
		failed[k] = true
	}
	counts := map[string]int{sourceCVEList: 0, nvd.Name: 0}
	seen := map[string]bool{}
	for _, f := range fs {
		p := byName[f.Product]
		if len(p.Entry.NVD) == 0 || failed[sourceCVEList+"/"+p.Name] || failed[nvd.Name+"/"+p.Name] || seen[p.Name+"/"+f.ID] {
			continue
		}
		seen[p.Name+"/"+f.ID] = true
		var found []string
		for _, s := range compared {
			if slices.Contains(f.Sources, s) {
				found = append(found, s)
			}
		}
		if len(found) != 1 {
			continue
		}
		counts[found[0]]++
		logx.Audit(ctx, log, "finding found only by one source", "found_only_by", found[0], "product", p.Name, "id", f.ID)
	}
	log.Info("source coverage", "cvelist_only", counts[sourceCVEList], "nvd_only", counts[nvd.Name])
	return counts
}
