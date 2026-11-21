# Development

```sh
make lint         # go vet + golangci-lint
make test         # go test -race ./...
make build
make chart-sync   # after editing defaults/*.yaml: the chart ships copies (CI checks)
go test ./internal/output/... -update   # refresh golden files after output changes
make triage-eval  # Claude triage regression set, real API (ANTHROPIC_API_KEY)
```

`make triage-eval` sends a fixed set of findings (KEV-listed, prompt
injection in the description, not affected, unknown match, ...) to Claude
with the configured model and effort (`CLAUDE_MODEL`, `CLAUDE_EFFORT`) and
checks each verdict against bounds, before the rules' floor. Run it before
changing the model, the effort or the prompt; without the key it skips.

```
cmd/vulnwatch/          main
defaults/               built-in config.yaml and sources.yaml (go:embed)
internal/cli/           commands
internal/config/        file loading, merging, validation; stack.yaml and tenants
internal/catalog/       product resolution, aliases, image matching
internal/helmchart/     versions from Helm charts
internal/discover/      stack discover, diff and merge
internal/kube/          read-only Kubernetes client
internal/imageref/      image references and tag versions
internal/sources/       ghsa, osv, cvelist, nvd, k8sfeed, rss, kev, epss, redhat, trivy, ostracker
internal/finding/       finding model, dedup, change detection
internal/match/         version parsing and matching
internal/triage/        Claude triage and rule-based fallback
internal/pipeline/      run, bootstrap and audit
internal/report/        output-independent report model
internal/output/        stdout, json, html, slack
internal/metrics/       Prometheus metrics
internal/state/         SQLite state
internal/httpx/         HTTP client with retries and limits
internal/logx/          log format and levels (audit)
internal/safe/          panics in parsers become errors
internal/sandbox/       Landlock restrictions for run and bootstrap
internal/brand/         terminal splash
version/                version (set at build time)
charts/vulnwatch/       Helm chart, Grafana dashboards, alert rules
```

## Adding a product

Add it to the catalog in an override file (or `defaults/sources.yaml` to share
it); no code change:

```yaml
catalog:
  velero:
    aliases: [vmware-velero]
    ghsa: [vmware-tanzu/velero]                                     # repos with security advisories
    osv: [{ ecosystem: Go, package: github.com/vmware-tanzu/velero }]
    nvd: ["cpe:2.3:a:vmware:velero"]                                # CPE prefix
    rss: []
    images: [velero/velero]                                         # for stack discover and Trivy
```

Check it with `vulnwatch catalog show velero` and
`vulnwatch sources test --product velero --days 365`. If the product is
deployed by a Helm chart, add the chart to `helm_charts` too. When sharing it
in `defaults/sources.yaml`, mark selectors `[v]` only after seeing data, and
say in the pull request what each source returned.

A new *source type* goes under `internal/sources/<name>/` implementing
`sources.Source` (or `sources.Enricher`), with its settings in
`internal/config/schema.go`, its URLs in `sources.yaml` (never in Go code),
registration in `pipeline.BuildSources` and an `httptest` test with a recorded
fixture.

## Releasing

Between releases the version is `vX.Y.Z-dev` and `main` builds are
`vX.Y.Z-dev.<sha>`. To release:

1. Set `Version` in [`version/version.go`](../version/version.go) to `vX.Y.Z` and
   `version`/`appVersion` in [`Chart.yaml`](../charts/vulnwatch/Chart.yaml) to
   `X.Y.Z` (CI checks they match), commit.
2. Tag that commit and push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`.
   The `ci` workflow publishes the image `ghcr.io/vasops/vulnwatch:X.Y.Z` and
   the chart `oci://ghcr.io/vasops/charts/vulnwatch` `X.Y.Z`, signs both and
   creates the GitHub release with the binaries.
3. Set the next `-dev` version in both files.
