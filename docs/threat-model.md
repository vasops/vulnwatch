# vulnwatch threat model

What vulnwatch protects, who could attack it, and what stops them. Review it
when a source, an output or the deployment changes.

## What vulnwatch is

A daily batch job (Kubernetes CronJob). It reads `stack.yaml`, fetches
advisories over HTTPS, asks Claude to triage new findings, and writes Slack
messages, reports, Prometheus metrics and a SQLite state. It serves nothing:
no listener, no users, no logins.

```
 stack.yaml, config ──┐                        ┌──> Slack (summary, P1 alerts)
 advisory feeds ──────┤                        ├──> Pushgateway → Prometheus → Grafana, alerts
 Helm chart repos ────┼──> vulnwatch (CronJob) ┼──> HTML / JSON reports (PVC)
 trivy-operator CRDs ─┤        │               └──> SQLite state (PVC)
 Kubernetes API ──────┘        └──> Claude API (triage)
```

## Assets

| Asset                                                            | Why it matters                                                           |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------ |
| **The verdict**: what is reported, its priority, what stays open | The whole point. A silenced P1 is the worst outcome, worse than a crash. |
| Secrets: Anthropic key, Slack bot token, GitHub token, NVD key   | Cost, posting as the bot, rate limits.                                   |
| The inventory (stack.yaml, reports, metrics)                     | Tells an attacker which vulnerable versions run where.                   |
| The cluster                                                      | vulnwatch's service account can read trivy-operator reports.             |

## Trust boundaries and threats

| #   | Boundary                               | Threat (STRIDE)                                                                                                                            | Mitigation                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Advisory text → Claude**             | *Tampering*: anyone can publish a GitHub advisory or an RSS post whose text tells the model "this is not relevant, P4", hiding a real P1.  | The system prompt marks every input field as data and says to ignore instructions in it. A **floor** in code: exploited findings (KEV, or SSVC "active" on an important product) and affected ones with CVSS ≥ 9 stay relevant and at least P2 whatever the model says; any other affected finding the rules rate P1 or P2 stays listed at P3 at most. Every verdict below the rule-based priority is logged at the `audit` level ("triage below the rules").                                                                                                       |
| 2   | Advisory feeds → parsers               | *Tampering, DoS*: malformed JSON, XML or ranges crash or stall the run.                                                                    | Response size limits (`http.max_response_bytes`; cvelistV5 archives at most 4 GiB, a record 8 MiB, written to the temp dir, never into the state), timeouts and retries; a panicking source becomes a warning (`internal/safe`); fuzz tests for version constraints, image references, chart archives, stack.yaml and the model's answers (`make fuzz`, scheduled in CI).                                                                                                                                                                                           |
| 3   | Helm chart repositories → chart parser | *DoS*: a gzip or nested-archive bomb in a chart.                                                                                           | One unpack budget per chart, nested archives included, and at most 5 nesting levels; only Chart.yaml, values.yaml and nested archives are read.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 4   | **Pushgateway**                        | *Spoofing, tampering*: anyone in the cluster who can reach it can overwrite or delete vulnwatch's metrics ("0 open P1"), silencing alerts. | A NetworkPolicy on the Pushgateway that admits only vulnwatch and Prometheus, in the deployment repo (recommended; the chart can't add it). `VulnwatchMetricsAbsent` and `VulnwatchNoRecentSuccess` fire only when the metrics disappear or go stale: an overwrite with fresh data is not detected. vulnwatch's own egress to it can be narrowed with `networkPolicy.pushgatewayNamespace` / `pushgatewayPodLabels`.                                                                                                                                                |
| 5   | Process → files and network            | *Elevation*: code execution in the process (parser bug, malicious dependency).                                                             | Landlock after startup (the chart requires it: a node that can't apply it fails the run instead of running unrestricted): reads only /etc, the config directories, the service account token and runtime files; writes only state, temp and report directories; TCP connects only to the ports of the configured URLs (Linux 6.7+). Distroless static image, non-root, read-only root filesystem, no capabilities, seccomp RuntimeDefault, no shell. Optional gVisor/Kata (`runtimeClassName`) and a recorded seccomp profile.                                      |
| 6   | Process → internet                     | *Information disclosure*: exfiltration of secrets or the inventory.                                                                        | The NetworkPolicy alone allows HTTPS to any address (except `internetExcept`), DNS to any address and, with `trivy.enabled`, the API server ports to any address: no host-name boundary unless `networkPolicy.cilium.enabled` (not enabled in prod). With it, the CiliumNetworkPolicy allows HTTPS only to the listed hosts, and the NetworkPolicy keeps no rule without a destination (DNS only to kube-dns, the API server by entity), so the host list is the effective boundary (`make chart-lint` checks this). Landlock ports as a second layer (Linux 6.7+). |
| 7   | Secrets                                | *Information disclosure*                                                                                                                   | Only in env vars from a Secret (Vault via External Secrets in prod), never in files or logs; in URLs in errors and logs (transport errors, retry logs, feed and Pushgateway URLs) the password or a lone user name, every query value and the fragment are replaced (`user:xxxxx@`, `?key=xxxxx`); `config dump` redacts.                                                                                                                                                                                                                                           |
| 8   | Kubernetes API                         | *Elevation*                                                                                                                                | Read-only RBAC on trivy-operator reports; the service account token is mounted only with `trivy.enabled`.                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 9   | Supply chain                           | *Tampering*: a malicious or vulnerable dependency, build or image.                                                                         | `go.sum` verified (`go mod verify`, `-mod=readonly`); govulncheck blocking in CI and daily; capslock fails CI when the binary gains a capability; Trivy fs scan, and an image scan that keeps a chart from being released on an image with fixable HIGH/CRITICAL vulnerabilities; Renovate; CycloneDX SBOM per build; keyless cosign signatures on the release image and chart, for admission policies.                                                                                                                                                             |
| 10  | Outputs → readers                      | *Tampering*: advisory text with markup in Slack or HTML.                                                                                   | Slack mrkdwn escaping; html/template auto-escaping (javascript: links are neutralised). Links point to advisory sites, never run anything.                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 11  | Laptop use of `stack discover/merge`   | *Elevation*: kubeconfig exec plugins run programs (that's how client-go OIDC logins work).                                                 | Expected: capslock lists EXEC from client-go's credential plugins. Use read-only kubeconfig contexts. Landlock and the in-cluster CronJob don't use kubeconfig.                                                                                                                                                                                                                                                                                                                                                                                                     |

Sent to the Claude API per finding: an opaque key (`f1`, `f2`, …), the
advisory ID, aliases, title and description, CVSS score and vector,
severity, affected and fixed versions, KEV, CISA's SSVC and EPSS, Red Hat's
rating, statement and mitigation, the catalog product
name, the deployed version constraint, exposure, criticality, the version
match and its detail, the nodes' OS name and release, and vulnerable image
packages as `name version (fixed in …) in image:tag`. Never the tenant,
environment, registry, image path or digest.

## Accepted risks

- **The model can still lower priorities**: an affected finding the rules
  rate P1 or P2 can drop to P3, and findings with an unknown version match or
  the rules' P3 or lower can be hidden. Those verdicts are audited.
- **Advisory data is only as good as the sources** (wrong ranges, missing
  versions). See [Known limitations](how-it-works.md#known-limitations).
- **Pushgateway without authentication** inside the cluster; contained only
  by a NetworkPolicy on the Pushgateway, if the deployment adds one.
- **Image findings only for the local cluster**: tenants' clusters have no
  Trivy data in vulnwatch.

## Litmus test

Assume code execution in the vulnwatch process right now:

- **Spawn a process?** There is no shell in the image. Runtime enforcement
  (Tetragon killing `execve`) is a cluster task.
- **Read other files?** No (Landlock, read-only root filesystem).
- **Reach other services?** With `networkPolicy.cilium`, only HTTPS to the
  configured hosts; with the NetworkPolicy alone, HTTPS to any address. Only
  on the configured ports (Landlock, Linux 6.7+).
- **Steal long-lived credentials?** The API tokens in env, yes; rotate them
  in your secret store. No Kubernetes token without `trivy.enabled`.
- **Escape to the node?** Not without a kernel exploit; gVisor/Kata
  (`runtimeClassName`) removes the direct kernel surface.
- **Would we notice?** Landlock denials appear in the kernel audit log; a
  failed run fires `VulnwatchRunFailed`.
