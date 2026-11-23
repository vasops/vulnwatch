# Configuration

Three files. Only `stack.yaml` is yours; `config.yaml` and `sources.yaml` are
built into the binary (from [`defaults/`](../defaults)), and the files you pass
are layered over them:

| File                                       | Flag / env                          | Holds                                                                |
| ------------------------------------------ | ----------------------------------- | -------------------------------------------------------------------- |
| [`stack.yaml`](../examples/stack.yaml)     | `--config` / `STACK_CONFIG`         | what we run: products, versions, Helm releases, node OS, tenants     |
| [`config.yaml`](../defaults/config.yaml)   | `--app-config` / `VULNWATCH_CONFIG` | how vulnwatch runs: HTTP, run, triage, outputs, metrics              |
| [`sources.yaml`](../defaults/sources.yaml) | `--sources` / `VULNWATCH_SOURCES`   | where to look: source endpoints, product catalog, Helm chart mapping |

A key in the wrong file is an error that names the right one. Secrets are never
in files, only the names of the env vars that hold them.

## stack.yaml

```yaml
defaults:
  min_cvss: 4.0          # ignore findings below this unless KEV-listed
  exposure: internal     # internet | internal
  criticality: medium    # high | medium | low

helm:                    # charts you deploy: versions are read from the chart
  - { repo: https://argoproj.github.io/argo-helm, chart: argo-cd, version: 10.9.7 }
  - repo: https://charts.min.io/
    chart: minio
    version: 5.4.0
    versions: { minio: RELEASE.2025-04-22T22-12-26Z }   # your values pin another image

os:                      # the nodes: their kernel is watched as debian-13-kernel
  name: debian
  release: "13"
  kernel: "6.12.48 || 6.12.62"

products:                # everything else
  postgresql: "17.4"
  kubernetes: ">=1.33.0"
  keycloak:
    version: "26.7.0"
    exposure: internet
    criticality: high
```

| Constraint | Example                   | Meaning                              |
| ---------- | ------------------------- | ------------------------------------ |
| exact      | `1.8.1`, `v1.30.4+rke2r1` | that version (best results)          |
| wildcard   | `26.x`, `26.1.x`, `1.8`   | that release line                    |
| range      | `>=10.4 <11`              | all versions in between              |
| union      | `20.0.3 \|\| 26.7.0`      | several deployments; each is checked |
| all        | `*`                       | always "depends"; left to triage     |

- Product names come from the catalog in `sources.yaml` (aliases work, typos
  get a suggestion).
- Helm charts are downloaded anonymously (classic repos and `oci://`) and cached
  in the state DB. Which products a chart contains is the `helm_charts`
  mapping in `sources.yaml`. vulnwatch reads the chart's defaults, not your
  values: set `versions:` when you pin a different image.
- A product listed several times (two charts, or a chart and `products`) is
  checked for every version.
- Per-product settings: the product's own > `defaults` in stack.yaml >
  `product_defaults` in config.yaml.

## Generating it from a cluster

`vulnwatch stack discover` writes a stack.yaml from what runs in the current
kubeconfig context (`--context`, `--kubeconfig`, `-o file`):

| Read from                                                   | Becomes                                                                             |
| ----------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Argo CD Applications with a Helm chart                      | `helm:` entries; `versions:` where the running image differs from the chart default |
| Helm release Secrets (`helm install`)                       | `products:` (a release record has no repository URL)                                |
| running Pods and CronJob templates                          | `products:`, by the catalog's `images:`                                             |
| the API server and nodes                                    | `kubernetes`, `rke2`/`k3s`, `containerd`, and `os:` (distribution, release, kernel) |
| Ingress, Gateway API routes, LoadBalancer/NodePort Services | `exposure: internet` on what they reach                                             |

Each entry has a comment saying where it came from. Images, charts and node
components vulnwatch doesn't know are listed as comments at the end: add
catalog entries for those worth watching. Criticality can't be read from a
cluster; set it by hand. Helm records of releases that Argo CD took over are
stale and skipped (with a warning).

The stack starts with `generated_at: "YYYY-MM-DD"`, the day (UTC) the cluster
was read. `stack merge` sets it to today in the stack it merges into: the
top level, or `tenants.<t>.environments.<e>`. The run exports it as
`vulnwatch_tenant_inventory_timestamp_seconds`, the overview dashboard
shows each environment's inventory age, and `VulnwatchInventoryStale` fires
when one is older than `prometheusRule.inventoryMaxAgeDays` (30). A stack
written by hand has no `generated_at`, and no alert.

`vulnwatch stack merge <file>` keeps an existing stack.yaml up to date, or a
Helm values file with the stack under `stack:` (`--key` for another path). It
edits the text in place, so formatting and comments are kept, and lists every
change:

```
helm argo-cd: 10.9.2 -> 10.9.7
helm loki: versions.loki = 3.6.9 (chart default 3.6.12)
helm vault: exposure: internet (HTTPRoute vault.example.com)
products.renovate: 43 -> 44.180 (docker.io/renovate/renovate:44.180 (renovate))
products.containerd: added 2.2.3 (container runtime on the nodes)
```

It never removes anything, because a stack may cover several clusters:
versions the file already allows stay, a union gets the new version added, and
an explicit `exposure` is kept. `--dry-run` prints the result instead of
writing it.

`vulnwatch stack diff` compares stack.yaml with the cluster; `--exit-code`
exits 1 on drift or products not in the stack, for CI:

```
PRODUCT     STACK             CLUSTER  STATUS
loki        3.6.12            3.6.9    drift            values pin another image
dragonfly   -                 v1.38.2  not in stack     runs, but isn't watched
keycloak    26.7.0 || 20.0.3  26.7.0   stale: 20.0.3    only adds findings
gitlab-ce   19.5.3            -        not in cluster   fine outside Kubernetes
```

A scheduled drift check (`stack diff --exit-code` per tenant environment)
needs read access to every tenant's cluster, so it belongs outside the
scanner: a CI job or a separate CronJob with those kubeconfigs. vulnwatch
reads only its own cluster and doesn't run one; it watches the inventory age
(`generated_at`) instead.

**What isn't watched.** `discover` ends the file with what the cluster runs but
vulnwatch can't watch: running images no catalog product claims, catalog
images without a version tag, and charts without a `helm_charts` mapping.
`merge` edits the file in place, so it prints the same notes, per cluster
and tenant. For each image, add a catalog entry with `images:` to watch it,
or put it on the `ignore_images` list in `sources.yaml` when it isn't worth
one: helper sidecars, your own images, software without any advisory
source. The built-in list covers the common helpers; add your own images in
a sources override:

```yaml
ignore_images:
  own:                                     # a new group; drop one with []
    - registry.example.com/team/**         # "**": everything below
    - ghcr.io/example/*                    # "*": one path segment
```

Ignored images are left out of the notes and of Trivy's unmatched images;
Trivy still scans them.

All three commands only read the cluster (nodes, pods, cronjobs, services,
ingresses, routes, Argo CD applications; Secrets for Helm releases, skipped
without access). With `--tenant` and `--environment` they work on a tenant's
environment instead (see [Tenants](tenants.md#tenants)).

## config.yaml and sources.yaml

You only write what differs from the built-in files. Pass overrides with
`--app-config` / `--sources` (repeat them, or comma-separate the env vars);
each file is merged on top of the previous one: maps merge, lists replace,
`enabled: false` switches off a source or catalog product. See
[`examples/sources-override.yaml`](../examples/sources-override.yaml).

```sh
vulnwatch config defaults sources > my-sources.yaml   # start an override from the built-in file
vulnwatch config dump                                 # the merged result, secrets redacted
```

`--no-defaults` (`VULNWATCH_NO_DEFAULTS=true`) leaves the built-in files out;
both kinds of file are then required.

## Environment variables

| Variable                                      | Purpose                                                                                                                        |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `ANTHROPIC_API_KEY`                           | Claude; required for `run` with triage enabled                                                                                 |
| `GITHUB_TOKEN`                                | GitHub API; recommended                                                                                                        |
| `NVD_API_KEY`                                 | NVD request spacing 6s → 1s                                                                                                    |
| `SLACK_BOT_TOKEN`, `SLACK_CHANNEL`            | Slack output: bot token and summary channel ID                                                                                 |
| `SLACK_ALERT_CHANNEL`                         | channel ID for P1 alerts (default: `SLACK_CHANNEL`)                                                                            |
| `SLACK_NEWS_CHANNEL`                          | channel ID for `vulnwatch news` (default: `SLACK_CHANNEL`)                                                                     |
| webhook output's `url_env`/`alert_url_env`/`headers_env` | your own names: the main URL, the P1 alert URL (default: the main URL) and any extra headers — see [Outputs](outputs.md#outputs) |
| pagerduty output's `routing_key_env`                     | your own name: the PagerDuty Events API v2 integration key — see [Outputs](outputs.md#outputs) |
| teams output's `url_env`/`alert_url_env`      | your own names: the Workflows webhook URL for the run summary, and for P1 alerts (default: the same URL) — see [Outputs](outputs.md#outputs) |
| `CLAUDE_MODEL`, `CLAUDE_EFFORT`               | override `triage.model` (`claude-haiku-5-5`) and `triage.effort` (`high`)                                                      |
| `REPORT_LANGUAGE`, `MAX_LLM_FINDINGS`         | override `triage.language` and `triage.max_findings`                                                                           |
| `STACK_CONFIG`, `STATE_DB`                    | file locations (defaults `./stack.yaml`, `./vulnwatch.db`)                                                                     |
| `VULNWATCH_CONFIG`, `VULNWATCH_SOURCES`       | override files layered over the built-in defaults (comma-separated)                                                            |
| `VULNWATCH_NO_DEFAULTS`                       | `true`: leave the built-in config.yaml and sources.yaml out                                                                    |
| `VULNWATCH_LOG_LEVEL`, `VULNWATCH_LOG_FORMAT` | see [Logging](cli.md#logging)                                                                                                  |
| `VULNWATCH_LANDLOCK`                          | `require`: fail when Landlock can't be applied; `false`: run without it; default `true` (see [Security](security.md#security)) |
| `VULNWATCH_MEMORY_LIMIT`                      | container memory limit in bytes (the chart sets it); the Go soft limit becomes 90% of it unless `GOMEMLIMIT` is set            |

Flags beat env vars, env vars beat files.
