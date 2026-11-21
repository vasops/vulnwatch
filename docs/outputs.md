# Outputs and metrics

## Outputs

All outputs link each finding to its **NVD record** and **GitHub advisory**
(links come from `detail_url` in `sources.yaml`).

- **stdout:** readable text, colored on a TTY.
- **json:** the full report model.
- **html:** one self-contained file, light/dark, mobile-friendly.
- **slack:** short on purpose; details live in Grafana and the HTML/JSON report.
  - **Run summary** to `SLACK_CHANNEL`: P1 count, new and open counts per
    priority (open as on the dashboard: new plus still open), the new and
    updated findings (most urgent first, up to 10 and as many as fit in
    Slack's 3000 characters, the rest as "+N more") with product, version,
    advisory link, why it was updated and the action, and a link to the
    Grafana dashboard for this run (`outputs.slack.dashboard_url`,
    `{from}`/`{to}` become `now-30d`/`now`). A finding in several tenant environments
    is one line (`acme: prod, stage; beta: prod`). When a source failed, the
    summary says the run is incomplete and names the source.
  - **P1 alert** to `SLACK_ALERT_CHANNEL`: one card per P1 found in this run,
    with a plain-language explanation, severity, fix (the version to upgrade
    to first), exploitation (KEV and EPSS), whether our version is affected,
    the action and the links. More than 5 P1s from full-history checks (a new
    tenant, a lost state) share one card.
  - **Tenants** with their own `slack.channel` get their own summary and
    alerts (see [Tenants](tenants.md#tenants)).
  - **At-least-once:** a P1 is alerted when new or materially changed. A
    failed post fails the run after every other channel was posted, and the
    state is not written, so the next run posts again: channels that worked
    may see the same messages twice.
  - Advisory text is escaped and only `https` links without markup
    characters are linked, so a source cannot inject mentions or links.

**Slack app:** create an app at api.slack.com/apps, add the bot scope
`chat:write`, install it, put the `xoxb-…` token in `SLACK_BOT_TOKEN`, invite
the bot to every channel and use channel **IDs** (`C0…`, in the channel
details). The app icon is [`logo/icon-512.png`](../logo/icon-512.png) on
`#0B1410`.

## Metrics and dashboards

vulnwatch is a batch job, so it **pushes** its metrics to a Pushgateway after
each run (not for dry runs); scrape the Pushgateway with `honor_labels: true`.

```yaml
# config.yaml
metrics:
  pushgateway_url: http://pushgateway.monitoring:9091
  job: vulnwatch
```

The Helm chart ships two Grafana dashboards and alert rules (per tenant,
environment and product):

| Dashboard                                                                                                           | Shows                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **vulnwatch · overview** ([json](../charts/vulnwatch/dashboards/vulnwatch-overview.json), uid `vulnwatch-overview`) | every tenant at a glance: open P1/P2/P3/P4 and KEV findings, days since the oldest open finding was first seen, the last run and the inventory age per tenant environment; the vulnerabilities affecting the most tenants; what was discovered when, everywhere. A tenant links to its dashboard. |
| **vulnwatch · tenant** ([json](../charts/vulnwatch/dashboards/vulnwatch.json), uid `vulnwatch`)                     | one tenant (`$tenant`, `$environment`): status, what was discovered when, open findings per product with version and upgrade target, every open finding with NVD/GitHub links, trends and source health.                                                                                          |

| Metric                                                                | Labels                                                                                  | Meaning                                                                         |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `vulnwatch_run_success`                                               | mode                                                                                    | 1 if the run and every output succeeded                                         |
| `vulnwatch_last_success_timestamp_seconds`                            |                                                                                         | last successful run                                                             |
| `vulnwatch_tenant_info`                                               | tenant, environment, local                                                              | the watched tenant environments (`local="true"`: the cluster vulnwatch runs in) |
| `vulnwatch_tenant_inventory_timestamp_seconds`                        | tenant, environment                                                                     | the stack's `generated_at` (00:00 UTC); only stacks that have one               |
| `vulnwatch_findings_new`                                              | tenant, environment, priority                                                           | reported in the last run                                                        |
| `vulnwatch_findings_open`                                             | tenant, environment, product, priority                                                  | affecting the stack now                                                         |
| `vulnwatch_findings_open_kev`, `…_open_unfixed`, `…_open_oldest_days` | tenant, environment, product                                                            | exploited, without a fix, days since the oldest was first seen                  |
| `vulnwatch_findings_open_image_only`                                  | tenant, environment, product                                                            | open findings only Trivy reports (fixed by a newer image)                       |
| `vulnwatch_finding_first_reported_timestamp_seconds`                  | tenant, environment, product, id, title, priority, fixed, image, nvd_url, github_url, … | per open finding: first reported time; `image` is `confirmed`, `only` or empty  |
| `vulnwatch_product_upgrade_info`                                      | tenant, environment, product, constraint, upgrade_to                                    | lowest version that fixes every open finding with a fix                         |
| `vulnwatch_source_findings`, `vulnwatch_source_errors`                | source                                                                                  | per-source yield and failures                                                   |
| `vulnwatch_findings_single_source`                                    | source                                                                                  | findings only cvelist or only NVD found in full-history checks (when both run)  |
| `vulnwatch_product_info`                                              | tenant, environment, product, constraint, exposure, criticality                         | the watched inventory                                                           |

Also: `vulnwatch_run_timestamp_seconds`, `vulnwatch_run_duration_seconds`,
`vulnwatch_findings_skipped`, `vulnwatch_findings_untriaged`,
`vulnwatch_triage_failures`,
`vulnwatch_image_findings_filtered`, `vulnwatch_images_unmatched`,
`vulnwatch_kernel_findings_filtered`, `vulnwatch_warnings`,
`vulnwatch_build_info`. Without tenants every series has `tenant="local"`,
`environment="default"` (or the names set at the top of stack.yaml).

The metrics describe each tenant's inventory: `vulnwatch_product_info`,
`vulnwatch_product_upgrade_info` and
`vulnwatch_finding_first_reported_timestamp_seconds` carry the products,
their versions and the open CVE IDs; `vulnwatch_findings_open*` and
`vulnwatch_tenant_info` the products and tenant names. If tenants ever get
access to the monitoring, give each a datasource (or a label-enforcing
proxy) restricted to its own `tenant` label, not the shared one.
