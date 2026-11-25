# Outputs and metrics

## Outputs

All outputs link each finding to its **NVD record** and **GitHub advisory**
(links come from `detail_url` in `sources.yaml`).

- **stdout:** readable text, colored on a TTY.
- **json:** the full report model.
- **html:** one self-contained file, light/dark, mobile-friendly.
- **slack:** short on purpose; details live in Grafana and the HTML/JSON report.
  - **Run summary** to `SLACK_CHANNEL`: the P1 count, new and open counts
    per priority (open as on the dashboard: new plus still open), the new
    and updated findings, and a link to the Grafana dashboard for this run
    (`outputs.slack.dashboard_url`, `{from}`/`{to}` become `now-30d`/`now`).
    When a source failed, the summary says the run is incomplete and names
    the source.
    - **One entry per finding**, an advisory for a product, most urgent
      first: the full title, one action, the advisory link, why it was
      updated, and under it the tenant environments it affects with their
      versions. Environments share a line when they have the same version and
      the same priority; an environment where the finding has a lower
      priority gets its own line, marked with that priority's emoji. The
      action is the one most environments share. At most 10 findings are listed, then
      `+N more on the dashboard`; environments that do not fit in a section
      become `+N more environments`.
    - **Counts** are findings, with the number of environments next to them
      when it is larger: `N critical (P1) finding(s) in M environments`,
      `New: N in M environments`. `Open` stays per environment, so it matches
      the `findings_open` metric. Without tenants every count is as before.
    ```
    :red_circle: debian-13-kernel · CVE-2026-98432
    ipv4: free inet_opt and ireq_opt after an RCU grace period
          ↳ Upgrade the debian-13 kernel on all Kubernetes nodes to 6.12.113-1 or later.
          • acme: dev; globex: test · `6.12.95`
          • acme: prod · `6.12.95, 6.12.101`
          • initech: prod · `6.12.62`
    ```
  - **P1 alert** to `SLACK_ALERT_CHANNEL`: one card per P1 finding found in
    this run, not one per environment, with a plain-language explanation,
    severity, fix (the version to upgrade to first), exploitation (KEV and
    EPSS), the action and the links. With one environment the card says
    whether our version is affected; with several it has an `Affected` list
    of the environments where the finding is P1, with their versions. More
    than 5 P1 findings from full-history checks (a new tenant, a lost state)
    share one card, which groups environments the same way.
  - **Weekly report** (`outputs.slack.weekly`, off by default): once a week
    the daily run also posts, after the summary and the P1 alerts, one
    message per channel (the summary's channel, not the alert channel)
    about the time since the last weekly report (seven days when there is
    none, or it is more than 14 days old): open findings per priority (per
    environment, like `Open` in the summary), the findings first reported
    and the findings closed in the week, and the five open the longest
    among those reported before the week. The header names the tenant when
    the channel serves one, and the window's first and last day.
    Closed findings say why: `fixed`, `removed from the stack`,
    `advisory rejected` or `no longer relevant` (see
    [closures](how-it-works.md#closed-findings)). Findings are grouped across
    environments like the summary; no versions. At most 10 new and 10 closed
    findings are listed, then `+N more on the dashboard`. A channel with
    nothing open, new or closed gets `Nothing open. Nothing new or closed this
    week.` The stdout output prints the same parts after its report.
    ```
    :calendar: vulnwatch weekly · acme · 16 – 23 Nov 2026
    Open: 4   :red_circle: 2   :large_orange_circle: 2
    New this week: 2 · Closed this week: 2 in 3 environments

    New this week
    :red_circle: debian-13-kernel · CVE-2026-98432  ipv4: free inet_opt and ireq_opt after an RCU grace period
          • acme: dev, prod
    :large_orange_circle: keycloak · CVE-2026-11111  Open redirect in the login flow
          • acme: prod

    Closed this week
    keycloak · CVE-2026-22222 · fixed
          • acme: dev, prod
    grafana · CVE-2026-33333 · removed from the stack
          • acme: stage

    Open the longest
    :large_orange_circle: postgresql · CVE-2025-44444 · 142 days
          ↳ Upgrade to 17.6 or later.
          • acme: prod
    ```
    It is due when today (the job's local time) is `outputs.slack.weekly.day`
    and none was sent today, or when the last one is more than seven days
    old (a missed week is caught up the next day and covers the whole gap).
    After enabling, the first one waits for that day. A run limited with
    `--product` sends none without `--weekly`, and `bootstrap` sends none.
    When a due report was sent is kept in the state with the run, so a
    failed run or post repeats it the next day and a rerun does not; the
    very first report after enabling is the exception (see
    [Configuration](configuration.md#configyaml-and-sourcesyaml)).
    `vulnwatch run --weekly` sends it on any day without recording it, so
    the schedule and the next report's window stay; with
    `--dry-run --output stdout` it is a preview. In the JSON output, the
    weekly data's `from` and `until` carry the time zone of the run, unlike
    the other times of the report, which are UTC.
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
    fields as the Slack P1 card for one environment, no card-collapsing (a JSON payload has no
    text-length limit to fit). With tenants it stays one record per tenant
    environment; the receiver decides how to merge them:
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
    own; without tenants the key is the one above. PagerDuty stays one
    incident per tenant environment, unlike Slack and Teams, because
    environments are acknowledged and resolved separately.
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
  per P1 finding.
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
    sources"` fact and the dashboard button are omitted when empty. The
    counts are findings (an advisory for a product); when they span more
    tenant environments than findings, the number follows (`2 new finding(s)
    in 5 environments`). `Open` stays per environment.
  - **P1 alert**, one card per P1 finding found in this run (new/updated, or
    found by a full-history check) POSTed to `outputs.teams.alert_url_env`'s URL,
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
    The example is a finding without tenants. A finding in several tenant
    environments is still one card: the heading ends with `· N environments`
    and the product is shown without an environment, the `Version` fact is
    replaced by a bold `Affected` text and a second fact list with one fact
    per group of environments on the same version (title: the versions,
    value: the environments, e.g. `acme: dev; globex: test`), at most 20
    lines and then `+N more environments`. A finding with one environment
    keeps the card above.
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

| Metric                                                                | Labels                                                                                  | Meaning                                                                                    |
| --------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `vulnwatch_run_success`                                               | mode                                                                                    | 1 if the run and every output succeeded                                                    |
| `vulnwatch_last_success_timestamp_seconds`                            |                                                                                         | last successful run                                                                        |
| `vulnwatch_tenant_info`                                               | tenant, environment, local                                                              | the watched tenant environments (`local="true"`: the cluster vulnwatch runs in)            |
| `vulnwatch_tenant_inventory_timestamp_seconds`                        | tenant, environment                                                                     | the stack's `generated_at` (00:00 UTC); only stacks that have one                          |
| `vulnwatch_findings_new`                                              | tenant, environment, priority                                                           | reported in the last run                                                                   |
| `vulnwatch_findings_open`                                             | tenant, environment, product, priority                                                  | affecting the stack now                                                                    |
| `vulnwatch_findings_open_kev`, `…_open_unfixed`, `…_open_oldest_days` | tenant, environment, product                                                            | exploited, without a fix, days since the oldest was first seen                             |
| `vulnwatch_findings_open_image_only`                                  | tenant, environment, product                                                            | open findings only Trivy reports (fixed by a newer image)                                  |
| `vulnwatch_finding_first_reported_timestamp_seconds`                  | tenant, environment, product, id, title, priority, fixed, image, nvd_url, github_url, … | per open finding: first reported time; `image` is `confirmed`, `only` or empty             |
| `vulnwatch_product_upgrade_info`                                      | tenant, environment, product, constraint, upgrade_to                                    | lowest version that fixes every open finding with a fix                                    |
| `vulnwatch_source_findings`, `vulnwatch_source_errors`                | source                                                                                  | per-source yield and failures                                                              |
| `vulnwatch_findings_single_source`                                    | source                                                                                  | findings only cvelist or only NVD found in full-history checks (when both run)             |
| `vulnwatch_triage_requests`                                           | model                                                                                   | Claude triage requests that got a response in the last run                                 |
| `vulnwatch_triage_tokens`                                             | model, type                                                                             | tokens used in the last run; `type` is `input`, `output`, `cache_creation` or `cache_read` |
| `vulnwatch_product_info`                                              | tenant, environment, product, constraint, exposure, criticality                         | the watched inventory                                                                      |

Also: `vulnwatch_run_timestamp_seconds`, `vulnwatch_run_duration_seconds`,
`vulnwatch_findings_skipped`, `vulnwatch_findings_untriaged`,
`vulnwatch_triage_failures`,
`vulnwatch_image_findings_filtered`, `vulnwatch_images_unmatched`,
`vulnwatch_kernel_findings_filtered`, `vulnwatch_warnings`,
`vulnwatch_build_info`. Without tenants every series has `tenant="local"`,
`environment="default"` (or the names set at the top of stack.yaml).

The two triage families are set only when at least one Claude request got a response, all four
token types with zeros included. They are per run, not per tenant. A run that
fails before the report is built pushes health metrics only, so the families
keep the last successful run's values and the tokens of the failed run are not
exported. The same numbers are in the `triage usage` log line and in the JSON
report as `triage_usage` (`model`, `requests`, `input_tokens`, `output_tokens`,
`cache_creation_input_tokens`, `cache_read_input_tokens`), absent when no
Claude request got a response. The tenant dashboard shows them in the panels **Triage tokens
per run** and **Triage requests**, in the row "Runs and sources".

The metrics describe each tenant's inventory: `vulnwatch_product_info`,
`vulnwatch_product_upgrade_info` and
`vulnwatch_finding_first_reported_timestamp_seconds` carry the products,
their versions and the open CVE IDs; `vulnwatch_findings_open*` and
`vulnwatch_tenant_info` the products and tenant names. If tenants ever get
access to the monitoring, give each a datasource (or a label-enforcing
proxy) restricted to its own `tenant` label, not the shared one.
