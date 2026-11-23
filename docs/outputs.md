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

- **webhook:** POSTs plain JSON to your own HTTP endpoint (middleware, an
  internal system) — no per-service integration to write.
  ```yaml
  # config.yaml
  outputs:
    webhook:
      url_env: WEBHOOK_URL              # the run summary, and P1 alerts without alert_url_env
      alert_url_env: WEBHOOK_ALERT_URL  # optional; unset: alerts go to url_env's URL too
      headers_env:                      # optional extra headers; values come from these env vars
        Authorization: WEBHOOK_AUTH_HEADER
      dashboard_url: ""                 # linked from the summary; {from}/{to} become now-30d/now
  ```
  - **Run summary**, one POST to `outputs.webhook.url_env`'s URL:
    ```json
    {
      "mode": "run",
      "since": "2026-10-10T06:00:00Z",
      "until": "2026-10-12T06:00:00Z",
      "total": 2,
      "counts": [{"priority": "P1", "count": 1}, "..."],
      "open": [{"priority": "P1", "count": 2}, "..."],
      "open_total": 4,
      "dashboard": "https://grafana.example/d/vulnwatch?from=now-30d&to=now",
      "failed_sources": ["nvd"]
    }
    ```
    `counts`/`open` always list all 4 priorities (`P1`-`P4`); `dashboard` and
    `failed_sources` are omitted when empty.
  - **P1 alert**, one POST per P1 found in this run (new/updated, or found by
    a full-history check) to `outputs.webhook.alert_url_env`'s URL — the same
    data as the Slack P1 card, no card-collapsing (a JSON payload has no
    text-length limit to fit):
    ```json
    {
      "priority": "P1",
      "id": "CVE-2026-1001",
      "product": "keycloak",
      "severity": "critical",
      "cvss": 9.8,
      "kev": true,
      "epss": 0.91234,
      "fixed": ["26.1.4"],
      "action": "Upgrade to 26.1.4 today.",
      "links": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1001", "..."]
    }
    ```
  - **Alert URL falls back to the main URL** when `alert_url_env` isn't set
    (or its env var is empty): both payloads POST to the same place.
  - **Headers**: `outputs.webhook.headers_env` maps a header name to the env
    var holding its value (e.g. `{Authorization: WEBHOOK_AUTH_HEADER}`) —
    auth tokens go through env vars only, never into YAML. A configured
    header whose env var is unset or empty **fails the run at startup** and
    names the variable, rather than POSTing an empty header all run.
  - Posted through the shared retrying client (retry on 429/5xx, the TLS
    floor, redacted URLs in logs); the response body is read but never
    decoded as JSON.
  - **At-least-once:** a failed POST (retries exhausted) fails the run, so
    the state isn't written and the next run posts everything again.

- **pagerduty:** triggers a real PagerDuty incident per P1, no webhook in
  between — POSTs straight to PagerDuty's own Events API v2 endpoint
  (`https://events.pagerduty.com/v2/enqueue`, fixed, not configurable).
  ```yaml
  # config.yaml
  outputs:
    pagerduty:
      routing_key_env: PAGERDUTY_ROUTING_KEY  # the Events API v2 integration key
  ```
  - Only **P1 findings** learned in this run trigger an event: new or
    updated, plus every P1 a full-history check found for the first time (a
    new tenant, a lost state), the same findings Slack, webhook and teams
    alert on. Every other priority, and the run summary, stay silent —
    PagerDuty is a page, not a report (see Slack/webhook above for that).
    A `bootstrap` of a stack with many open P1s pages for each of them: run
    it before the integration key is live if that is not what you want.
  - **Priority → severity:** P1 is the only priority this output ever sees,
    and it always maps to PagerDuty's `critical` severity — hardcoded, not
    the finding's own CVSS severity:
    ```json
    {
      "routing_key": "<PAGERDUTY_ROUTING_KEY>",
      "event_action": "trigger",
      "dedup_key": "vulnwatch:keycloak:CVE-2026-1001",
      "payload": {
        "summary": "CVE-2026-1001: Account takeover via crafted <redirect_uri>",
        "source": "keycloak",
        "severity": "critical",
        "component": "keycloak"
      }
    }
    ```
    `dedup_key` is stable per (scope, product, CVE/GHSA id): a re-triggered
    event updates the same PagerDuty incident instead of opening a new one.
    With tenants the scope prefixes the key
    (`vulnwatch:acme/prod:keycloak:CVE-2026-1001`), so the same finding in
    two tenant environments pages twice and each incident is acked on its
    own; without tenants the key is the one above.
  - Posted through the shared retrying client (retry on 429/5xx, the TLS
    floor); same **at-least-once** behavior as webhook — a rejected or
    failed POST (PagerDuty answers non-2xx, or retries are exhausted) fails
    the run, the state isn't written, and the next run pages again.
  - `PAGERDUTY_ROUTING_KEY` (or whatever env var `routing_key_env` names)
    never reaches a log line or `config dump` (redacted like the Slack bot
    token).
  - No auto-resolve: when a finding stops being open, vulnwatch never sends
    an `event_action: "resolve"` — closing or acknowledging the PagerDuty
    incident stays a human (or PagerDuty's own auto-resolve timeout) call.

  **Set up the PagerDuty side:** open the service in PagerDuty's Service
  Directory → **Integrations** tab → **Add another integration** → search
  for and select **Events API V2** → once added, open the integration's
  detail (the icon to its right) and copy its **Integration Key** — that's
  the value for `PAGERDUTY_ROUTING_KEY` (or your own env var named in
  `routing_key_env`), never written to YAML.
- **teams:** POSTs an **Adaptive Card** to a Microsoft Teams Workflows
  webhook — the same two moments as webhook/slack: one run summary, one card
  per P1.
  ```yaml
  # config.yaml
  outputs:
    teams:
      url_env: TEAMS_URL              # the run summary, and P1 alerts without alert_url_env
      alert_url_env: TEAMS_ALERT_URL  # optional; unset: alerts go to url_env's URL too
      dashboard_url: ""               # linked from the summary; {from}/{to} become now-30d/now
  ```
  - **Run summary**, one card POSTed to `outputs.teams.url_env`'s URL:
    ```json
    {
      "type": "message",
      "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
          "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
          "type": "AdaptiveCard",
          "version": "1.5",
          "msteams": {"width": "full"},
          "body": [
            {"type": "TextBlock", "text": "vulnwatch report · 12 Oct 2026", "size": "Medium", "weight": "Bolder", "wrap": true},
            {"type": "TextBlock", "text": "2 new finding(s), 4 open", "wrap": true},
            {"type": "FactSet", "facts": [
              {"title": "New", "value": "2 (P1: 1, P2: 1)"},
              {"title": "Open", "value": "4 (P1: 2, P3: 2)"},
              {"title": "Window", "value": "10 Oct 06:00 → 12 Oct 06:00 UTC"},
              {"title": "Failed sources", "value": "nvd"}
            ]}
          ],
          "actions": [{"type": "Action.OpenUrl", "title": "Open the dashboard", "url": "https://grafana.example/d/vulnwatch?from=now-30d&to=now"}]
        }
      }]
    }
    ```
    The heading turns `Attention` (red) when the run has a P1; the `"Failed
    sources"` fact and the dashboard button are omitted when empty.
  - **P1 alert**, one card per P1 found in this run (new/updated, or found
    by a full-history check) POSTed to `outputs.teams.alert_url_env`'s URL,
    with the same fields as the Slack/webhook P1 alert and an
    `Action.OpenUrl` button to the advisory (omitted when there is no link):
    ```json
    {
      "type": "message",
      "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
          "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
          "type": "AdaptiveCard",
          "version": "1.5",
          "msteams": {"width": "full"},
          "body": [
            {"type": "TextBlock", "text": "P1 · keycloak · CVE-2026-1001", "size": "Medium", "weight": "Bolder", "color": "Attention", "wrap": true},
            {"type": "FactSet", "facts": [
              {"title": "CVE", "value": "CVE-2026-1001"},
              {"title": "Product", "value": "keycloak"},
              {"title": "Version", "value": "26.x"},
              {"title": "Severity", "value": "critical"},
              {"title": "CVSS", "value": "9.8"},
              {"title": "KEV/EPSS", "value": "exploited in the wild (CISA KEV) · EPSS 91.2%"},
              {"title": "Fixed in", "value": "26.1.4"},
              {"title": "Action", "value": "Upgrade to 26.1.4 today."}
            ]}
          ],
          "actions": [{"type": "Action.OpenUrl", "title": "View advisory", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1001"}]
        }
      }]
    }
    ```
  - **Alert URL falls back to the main URL** when `alert_url_env` isn't set
    (or its env var is empty): both cards POST to the same place.
  - No extra headers: the Workflows webhook URL itself carries the
    authorization, posted through the shared retrying client (retry on
    429/5xx, the TLS floor, redacted URLs in logs); the response body is read
    but never decoded as JSON.
  - **At-least-once:** a failed POST (retries exhausted) fails the run, so
    the state isn't written and the next run posts everything again.
  - **Card schema 1.5.** Teams renders Adaptive Card 1.6 and older, on
    desktop and mobile; nothing newer is used. The legacy MessageCard format
    is deliberately not sent: a Workflows webhook still accepts it, but it
    cannot render buttons and Microsoft points new integrations at Adaptive
    Cards. Messages posted through a webhook always show the Workflows (Flow
    bot) identity — a custom bot name or icon is not available either way.

**Slack app:** create an app at api.slack.com/apps, add the bot scope
`chat:write`, install it, put the `xoxb-…` token in `SLACK_BOT_TOKEN`, invite
the bot to every channel and use channel **IDs** (`C0…`, in the channel
details). The app icon is [`logo/icon-512.png`](../logo/icon-512.png) on
`#0B1410`.

**Teams Workflows webhook:** Office 365 Connectors (the old "Incoming
Webhook" connector UI) were retired in May 2026; webhooks are now created
through the **Workflows** app, which is what this output POSTs its Adaptive
Cards to. In the target channel: **⋯ (more options) →
Workflows**, search for the **"Send webhook alerts to a channel"** template
(or build one from scratch with the **"When a Teams webhook request is
received"** trigger), point it at that channel, save, then copy the
generated webhook URL into `TEAMS_URL`. For P1s in a separate channel,
repeat in that channel and put its URL in `TEAMS_ALERT_URL`; without it, P1
alerts post to the same channel as the summary.

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
