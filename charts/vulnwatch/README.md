# vulnwatch Helm chart

Runs [vulnwatch](https://github.com/vasops/vulnwatch#readme) as a daily Kubernetes **CronJob**, with its
state on a PVC, metrics pushed to a Pushgateway, a Grafana dashboard and
Prometheus alert rules.

## Contents

- [Install](#install)
- [Minimal values](#minimal-values)
- [Values](#values)
- [Metrics, dashboard and alerts](#metrics-dashboard-and-alerts)
- [Trivy integration](#trivy-integration)
- [Argo CD](#argo-cd)
- [Operations](#operations)

## Install

The chart is published with every release (chart version = app version):

```sh
helm install vulnwatch oci://ghcr.io/vasops/charts/vulnwatch \
  --version 0.1.0 -n vulnwatch --create-namespace -f values.yaml
```

What it creates:

- **CronJob** (`concurrencyPolicy: Forbid`) running `vulnwatch run`;
  distroless nonroot image, read-only root filesystem, no capabilities, no
  service account token (unless `trivy.enabled`)
- **PVC** with the SQLite state and the latest `report.html` / `report.json`;
  kept on uninstall
- **ConfigMap** with `stack.yaml`, the built-in `config.yaml` and
  `sources.yaml` (copies of [`defaults/`](https://github.com/vasops/vulnwatch/tree/main/defaults)) and your overrides
- optional: a second CronJob running `vulnwatch news` hourly with its own
  PVC (`news.enabled`), bootstrap Job, Grafana dashboard ConfigMap, PrometheusRule,
  NetworkPolicy, read-only RBAC for trivy-operator reports, a Secret from
  values (testing only)

## Minimal values

```yaml
stack:                                  # what you run (format: examples/stack.yaml)
  products:
    keycloak: { version: "26.7.0", exposure: internet, criticality: high }
    postgresql: "17.4"
  os: { name: debian, release: "13", kernel: "6.12.48", criticality: high }  # the nodes' kernel

secrets:
  existingSecret: vulnwatch-envs        # ANTHROPIC_API_KEY, GITHUB_TOKEN, NVD_API_KEY, SLACK_BOT_TOKEN

run:
  outputs: [stdout, json, html, slack]

env:
  SLACK_CHANNEL: C0123456789            # run summary
  SLACK_ALERT_CHANNEL: C0987654321      # P1 alerts

metrics:
  pushgateway: { url: http://pushgateway.monitoring:9091 }
  dashboard:
    enabled: true
    url: https://grafana.example.com/d/vulnwatch/vulnwatch?from={from}&to={to}
  prometheusRule: { enabled: true }
```

## Values

| Key                                                               | Default                                                        | Description                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `image.repository` / `tag` / `digest`                             | `ghcr.io/vasops/vulnwatch`, appVersion                         | image; `digest` wins over `tag`                                                                                                                                                                                                                                                                                  |
| `schedule`, `timeZone`                                            | `0 6 * * *`, `Etc/UTC`                                         | when to run                                                                                                                                                                                                                                                                                                      |
| `suspend`                                                         | `false`                                                        | pause the CronJob                                                                                                                                                                                                                                                                                                |
| `activeDeadlineSeconds`                                           | `1800`                                                         | keep above `run.deadline` (20m)                                                                                                                                                                                                                                                                                  |
| `backoffLimit`                                                    | `0`                                                            | no retry (it would share `activeDeadlineSeconds`); state is written only after all outputs succeed, so the next run reports a failed run's findings again (Slack: at-least-once)                                                                                                                                 |
| `run.outputs`                                                     | `[stdout]`                                                     | `stdout`, `json`, `html`, `slack`; json/html go to `/data`                                                                                                                                                                                                                                                       |
| `run.logLevel`, `run.logFormat`, `run.extraArgs`                  | `info`, `json`, `[]`                                           | levels: debug, info, audit, warn, error (audit: what was reported and sent)                                                                                                                                                                                                                                      |
| `bootstrap.enabled`                                               | `false`                                                        | one-off full-history check after install; optional, the first run does it too                                                                                                                                                                                                                                    |
| `news.enabled`                                                    | `false`                                                        | a second CronJob runs `vulnwatch news`: each new Red Hat security bulletin and CERT-EU advisory (`sources.news`) posted once to `SLACK_NEWS_CHANNEL` (set it in `env`; else `SLACK_CHANNEL`), with the stack products its title names; the first check only remembers what is there; needs `persistence.enabled` |
| `news.schedule`, `news.outputs`, `news.activeDeadlineSeconds`     | `17 * * * *`, `[stdout, slack]`, `600`                         | `stdout`, `slack`                                                                                                                                                                                                                                                                                                |
| `news.repost`                                                     | `0`                                                            | post the newest N items of each feed again on every check (`--repost`), to see the first messages in the channel; set it back to `0` afterwards                                                                                                                                                                  |
| `news.persistence.size`                                           | `1Gi`                                                          | its own volume (class and access modes from `persistence`): what was posted                                                                                                                                                                                                                                      |
| `stack`                                                           | `{}`                                                           | stack.yaml inline…                                                                                                                                                                                                                                                                                               |
| `existingStackConfigMap.name` / `key`                             | `""` / `stack.yaml`                                            | …or from your own ConfigMap                                                                                                                                                                                                                                                                                      |
| `configOverride`                                                  | `{}`                                                           | layered on the built-in config.yaml (e.g. `triage: {enabled: false}`)                                                                                                                                                                                                                                            |
| `sourcesOverride`                                                 | `{}`                                                           | layered on the built-in sources.yaml (e.g. disable a catalog product)                                                                                                                                                                                                                                            |
| `trivy.enabled`                                                   | `false`                                                        | image findings from trivy-operator in this cluster, see [Trivy integration](#trivy-integration)                                                                                                                                                                                                                  |
| `secrets.existingSecret`                                          | `""`                                                           | Secret whose keys become env vars (use External Secrets)                                                                                                                                                                                                                                                         |
| `secrets.create` / `values`                                       | `false` / `{}`                                                 | create the Secret from values (testing only)                                                                                                                                                                                                                                                                     |
| `env`                                                             | `{}`                                                           | plain env vars, e.g. `SLACK_CHANNEL`, `CLAUDE_MODEL`                                                                                                                                                                                                                                                             |
| `secretEnv`, `envFromSecrets`, `envFrom`, `extraEnv`              |                                                                | other ways to pass env vars                                                                                                                                                                                                                                                                                      |
| `tmpDir.sizeLimit`                                                | `3Gi`                                                          | scratch at /tmp; the cvelist source reads the full CVE list there on its first run (about 1.3 GB)                                                                                                                                                                                                                |
| `persistence.enabled` / `size` / `storageClass` / `existingClaim` | `true` / `1Gi` / `""` / `""`                                   | state volume                                                                                                                                                                                                                                                                                                     |
| `metrics.pushgateway.url` / `job` / `grouping`                    | `""` / `vulnwatch` / `{}`                                      | where to push metrics                                                                                                                                                                                                                                                                                            |
| `metrics.dashboard.enabled` / `namespace` / `labels`              | `false` / release ns / `grafana_dashboard: "1"`                | Grafana dashboard ConfigMap for the sidecar                                                                                                                                                                                                                                                                      |
| `metrics.dashboard.url`                                           | `""`                                                           | dashboard link in Slack messages; `{from}`/`{to}` are filled in                                                                                                                                                                                                                                                  |
| `metrics.prometheusRule.enabled` / `labels`                       | `false` / `{}`                                                 | alert rules; add labels your Prometheus selects on                                                                                                                                                                                                                                                               |
| `metrics.prometheusRule.maxRunAgeHours`                           | `26`                                                           | alert when no run succeeded for this long                                                                                                                                                                                                                                                                        |
| `metrics.prometheusRule.inventoryMaxAgeDays`                      | `30`                                                           | alert when a stack's `generated_at` (written by `stack discover` / `stack merge`) is older than this many days                                                                                                                                                                                                   |
| `metrics.prometheusRule.findingAlerts`                            | `true`                                                         | alerts for open P1, KEV and public exploit findings                                                                                                                                                                                                                                                                          |
| `networkPolicy.enabled`                                           | `false`                                                        | egress only: DNS, HTTPS, Pushgateway port, and with `trivy.enabled` the API server                                                                                                                                                                                                                               |
| `networkPolicy.apiServerPorts`                                    | `[443, 6443]`                                                  | API ports allowed with `trivy.enabled` (service port and, after DNAT, the API server's)                                                                                                                                                                                                                          |
| `networkPolicy.pinDNS` / `dnsPeers`                               | `false` / kube-dns in kube-system                              | DNS only to these peers; always with `cilium.enabled`                                                                                                                                                                                                                                                            |
| `networkPolicy.pushgatewayNamespace` / `pushgatewayPodLabels`     | `""` / `{}`                                                    | where the Pushgateway runs; empty allows the port to any pod in the cluster                                                                                                                                                                                                                                      |
| `networkPolicy.cilium.enabled` / `fqdns` / `extraFQDNs`           | `false` / the default sources, Anthropic, Slack, GitHub / `[]` | egress by host name with a CiliumNetworkPolicy; the stack's Helm repositories are added automatically. The NetworkPolicy then has no rule without a destination (no any-address HTTPS, API server by entity, DNS to `dnsPeers`); keep `extraEgress` rules destination-bound too                                  |
| `resources`                                                       | 50m / 256Mi, limit 1Gi                                         | large Helm indexes are parsed in memory on first download; vulnwatch sets its Go soft limit to 90% of the memory limit                                                                                                                                                                                           |
| `runtimeClassName`                                                | `""`                                                           | e.g. `gvisor` or `kata` for kernel isolation                                                                                                                                                                                                                                                                     |
| `landlock`                                                        | `require`                                                      | `VULNWATCH_LANDLOCK`: `require` fails the run when the node can't apply Landlock (kernel, seccomp profile, gVisor); `"true"` runs unrestricted there with a warning; `"false"` turns it off                                                                                                                      |
| `podSecurityContext.seccompProfile`                               | `RuntimeDefault`                                               | or a profile recorded with Security Profiles Operator (`type: Localhost`)                                                                                                                                                                                                                                        |

Inside the pod, `run` restricts itself with Landlock to the files and ports it
needs (see [Security](https://github.com/vasops/vulnwatch/blob/main/docs/security.md)). By default (`landlock:
require`) a node that can't apply it fails the run (`vulnwatch_run_success`
0) instead of running unrestricted; set `landlock: "true"` for best effort or
`landlock: "false"` to turn it off.

All values are validated by [`values.schema.json`](https://github.com/vasops/vulnwatch/blob/main/charts/vulnwatch/values.schema.json); see
[`values.yaml`](https://github.com/vasops/vulnwatch/blob/main/charts/vulnwatch/values.yaml) for the rest (labels, annotations, security
contexts, node placement).

## Metrics, dashboard and alerts

vulnwatch pushes its metrics after each run. Run a Pushgateway (e.g. the
`prometheus-pushgateway` chart) and scrape it with `honor_labels: true`; that
chart's ServiceMonitor (`serviceMonitor.enabled: true`) sets it by default.

Two **dashboards** (one ConfigMap):

- **vulnwatch · overview** (uid `vulnwatch-overview`): every tenant at a
  glance. Status panels count open P1 and P2, KEV and public exploit
  findings. A table of tenant environments with open P1/P2/P3/P4 and KEV
  findings, days since the oldest open finding was first seen, the last
  run's new findings, the last run and the inventory age (days since
  `generated_at`); the vulnerabilities affecting the most tenants; what was discovered when, everywhere. Click a tenant to
  open its dashboard.
- **vulnwatch · tenant** (uid `vulnwatch`): run status, what was discovered
  in the selected period (and when), open findings per product with the
  version we run and the version to upgrade to, every open finding with when
  it was first reported and its NVD and GitHub links (tables mark KEV and
  public exploit findings in their own columns), trends and source health.
  The status row counts open KEV and public exploit findings in two panels.
  Tenant, environment, product and priority filters apply.

Without tenants in the stack there is one, `local/default`, and the tenant
dashboard is the one to use. Slack links open the tenant dashboard
(`metrics.dashboard.url`); a tenant's own channel gets a link that selects it.

The **alert rules**:

| Alert                                 | When                                                                                                                                                                                                                                          |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VulnwatchRunFailed`                  | the last run failed (also when Claude answered none of its triage calls: a bad API key or model name)                                                                                                                                         |
| `VulnwatchNoRecentSuccess`            | no successful run for `maxRunAgeHours`                                                                                                                                                                                                        |
| `VulnwatchMetricsAbsent`              | no metrics pushed for `maxRunAgeHours`                                                                                                                                                                                                        |
| `VulnwatchSourceFailing`              | a source failed for `sourceFailingFor` (1d)                                                                                                                                                                                                   |
| `VulnwatchSourceSilent`               | an advisory source (cvelist, NVD, OSV, GHSA) returned no findings in any run for 7 days                                                                                                                                                       |
| `VulnwatchTriageFailing`              | a Claude triage call failed in the last run (API error or invalid output): those findings have the rule-based priority                                                                                                                        |
| `VulnwatchInventoryStale`             | a tenant environment's (or the local stack's) `generated_at` is older than `inventoryMaxAgeDays` (30); none for stacks without it                                                                                                             |
| `VulnwatchP1Open`                     | a product has open P1 findings (per tenant and environment); `VulnwatchExploitedVulnerabilityOpen` and `VulnwatchPublicExploitOpen` stay quiet for it                                                                                         |
| `VulnwatchExploitedVulnerabilityOpen` | a product is affected by a KEV-listed vulnerability (per tenant and environment) and has no open P1 finding (`VulnwatchP1Open` covers that)                                                                                                   |
| `VulnwatchPublicExploitOpen`          | a product has an open finding with a public exploit (Metasploit module or Nuclei template; per tenant and environment) and neither `VulnwatchExploitedVulnerabilityOpen` (KEV) nor `VulnwatchP1Open` reports it: quiet where KEV or P1 alerts |

## Trivy integration

With [trivy-operator](https://github.com/aquasecurity/trivy-operator) in the
same cluster, `trivy.enabled: true` adds the vulnerable packages it finds in
the running images (see [Image findings](https://github.com/vasops/vulnwatch/blob/main/docs/how-it-works.md#image-findings-trivy)):

- turns on `sources.trivy` in the sources override
- creates a ClusterRole with `get` and `list` on
  `vulnerabilityreports.aquasecurity.github.io` only, bound to the service account
- mounts the service account token (it stays off without `trivy.enabled`)
- with `networkPolicy.enabled`, allows egress to the API server ports

Tune the filter with `sourcesOverride.sources.trivy` (`min_severity`,
`min_severity_internet`, `min_epss`). The first run with Trivy records the
current image findings as history and lists them under Still open.

## Argo CD

The chart works as an Argo CD Application without changes:

- The bootstrap Job is a `PostSync` hook. Argo CD runs it on every sync, so it
  runs `bootstrap --skip-if-initialized` and does nothing once a run succeeded.
- The PVC has `Prune=false,Delete=false`, so deleting the Application keeps the
  state.
- No `lookup` or `.Capabilities`; it renders the same with `helm template`.

## Operations

Run it now instead of waiting for the schedule:

```sh
kubectl -n vulnwatch create job --from=cronjob/vulnwatch vulnwatch-manual-$(date +%s)
```

- The latest `report.html` and `report.json` are on the PVC in `/data`; day to
  day, Slack and the Grafana dashboard are enough.
- To check a version before upgrading, run `vulnwatch audit --product <p>
  --version <v>` locally; it needs no state.
- Upgrading the chart never re-reports old findings: the state on the PVC
  remembers what was reported. Deleting the PVC starts over with a new
  full-history check.
