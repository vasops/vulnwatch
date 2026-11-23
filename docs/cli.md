# Commands and logging

## Commands

```
vulnwatch run                  the daily run
  --output stdout,json,html,slack   (default stdout)
  --html-path report.html  --json-path -     (- = stdout)
  --dry-run                    no state writes, no Slack
  --since 2026-10-01           override the window start
  --product keycloak           limit to products (repeatable; in every tenant)
  --weekly                     build and send the weekly report whatever the day, without recording it
                               (preview: --weekly --dry-run --output stdout); a run with --product never
                               sends it without --weekly
  --metrics-file f.prom        also write the metrics to a file
vulnwatch bootstrap            full-history check of every product, nothing reported as new
  --skip-if-initialized        no-op once a run succeeded (safe as a deploy hook)
vulnwatch audit                what affects the versions we run, from the full history (no state, no Claude)
  --product keycloak           limit to products (repeatable)
  --version 26.7.5             check a version before upgrading (needs one --product)
  --json  --fail-on-affected   machine-readable / non-zero exit for CI
vulnwatch news                 new security bulletins and alerts (sources.news), each posted once
  --output stdout,slack        (default stdout)
  --dry-run                    no state writes, no Slack
vulnwatch stack discover       write a stack.yaml from the current kubeconfig context
  --context  --kubeconfig  -o stack.yaml  --tenant  --environment
vulnwatch stack diff           compare stack.yaml with the cluster: drift, unwatched, stale
  --context  --kubeconfig  --exit-code  --tenant  --environment
vulnwatch stack merge <file>   merge the cluster into a stack.yaml or Helm values file
  --context  --kubeconfig  --key stack  --dry-run  --tenant  --environment
vulnwatch validate-config      validate the files, print where each product's data comes from
vulnwatch catalog list|show <product>
vulnwatch config dump          the merged config, secrets redacted
vulnwatch config defaults config|sources   the built-in file, to start an override from
vulnwatch sources test --product <p> [--days 30] [--json]   raw findings from one product's sources
vulnwatch version
```

Global flags: `--config`, `--app-config`, `--sources`, `--no-defaults`,
`--state-db`, `--log-level`, `--log-format`, `--landlock`. Logs go to stderr, reports to
stdout. The exit code is non-zero only when the run fails as a whole (invalid
config, a failed output, cancelled, or over `run.deadline`), never for a
failing source.

## Logging

Text on a terminal, JSON otherwise; `--log-format json|text` or
`VULNWATCH_LOG_FORMAT` choose explicitly. `--log-level` (or
`VULNWATCH_LOG_LEVEL`) sets the threshold, most verbose first:

| Level   | Logs                                                                                                                                                                                     |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `debug` | every source request, with its duration                                                                                                                                                  |
| `info`  | progress: run started, collected, finished (the default)                                                                                                                                 |
| `audit` | what vulnwatch decided and sent: every finding reported (tenant, product, version, ID, priority, decided by Claude or the rules), every Slack message (channel, kind), the state written |
| `warn`  | a source or a Helm chart failed, a check is incomplete                                                                                                                                   |
| `error` | an output failed, the run failed                                                                                                                                                         |

`--log-level audit` keeps exactly the decision trail plus warnings and errors:

```json
{"time":"…","level":"AUDIT","msg":"finding reported","tenant":"acme","environment":"prod","product":"keycloak","version":"25.0.6","id":"CVE-2026-15572","priority":"P2","relevant":"yes","decided_by":"llm","change":"new","kev":false,"cvss":8.8}
{"time":"…","level":"AUDIT","msg":"slack message posted","kind":"p1_alert","channel":"C0ACME","id":"CVE-2026-18963","text":"P1: acme/prod keycloak CVE-2026-18963"}
{"time":"…","level":"AUDIT","msg":"state written","reported":2,"history":14,"baselines":1}
```
