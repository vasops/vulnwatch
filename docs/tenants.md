# Tenants

One vulnwatch can watch the stacks of several customers, organizations or
teams. The top level of stack.yaml is the **local** stack: the cluster
vulnwatch runs in, the only one Trivy reads. Every other stack is a tenant's
**environment**, built from its cluster with `stack merge`:

```mermaid
%%{init: {"htmlLabels": false, "flowchart": {"htmlLabels": false}, "theme": "base", "themeVariables": {"lineColor": "#8A948F", "titleColor": "#FFFFFF", "primaryTextColor": "#FFFFFF", "textColor": "#7A8781"}}}%%
flowchart LR
  subgraph remote["Tenant clusters"]
    ap["acme / prod"]
    as["acme / stage"]
    gp["globex / prod"]
  end
  cli["vulnwatch stack merge<br/>one kubeconfig context<br/>per cluster"]
  ap -.-> cli
  as -.-> cli
  gp -.-> cli
  cli --> stack["stack.yaml<br/>local stack + tenants"]
  subgraph local["Local cluster · vasops/prod"]
    vw(["vulnwatch"])
    to["trivy-operator"]
  end
  stack --> vw
  to --> vw
  vw --> sd["Slack: default channels<br/>local stack, tenants<br/>without a channel"]
  vw --> sa["Slack: acme's channel<br/>acme's summary<br/>and P1 alerts"]
  vw --> gr["Grafana<br/>overview → tenant dashboard"]

  classDef input fill:#2563EB,stroke:#1E40AF,stroke-width:2px,color:#FFFFFF
  classDef source fill:#B45309,stroke:#78350F,stroke-width:2px,color:#FFFFFF
  classDef core fill:#138A4A,stroke:#0B5E31,stroke-width:3px,color:#FFFFFF,font-weight:bold
  classDef output fill:#15803D,stroke:#14532D,stroke-width:2px,color:#FFFFFF
  classDef support fill:#6D28D9,stroke:#4C1D95,stroke-width:2px,color:#FFFFFF
  classDef muted fill:#52525B,stroke:#27272A,stroke-width:2px,color:#FFFFFF
  classDef decision fill:#1F2937,stroke:#0B1410,stroke-width:2px,color:#FFFFFF
  class ap,as,gp,cli,stack input
  class to source
  class vw core
  class sd,sa,gr output
  style remote fill:#14213A,stroke:#3B82F6,color:#FFFFFF,stroke-width:2px,stroke-dasharray:6 4
  style local fill:#0F2A1A,stroke:#22A35E,color:#FFFFFF,stroke-width:2px,stroke-dasharray:6 4
```

```yaml
tenant: vasops           # how the local stack is named (default local/default)
environment: prod
defaults: { min_cvss: 4.0 }          # for every tenant
products: { keycloak: "26.7.0" }     # the local stack, as above

tenants:
  acme:
    defaults: { exposure: internet } # for all of acme's environments
    slack: { channel: C0ACME }       # acme's summary and P1 alerts go here
    environments:
      prod:
        generated_at: "2026-11-02"              # written by stack merge
        slack: { alert_channel: C0ACMEALERTS }  # this environment's P1 alerts
        helm: [ ... ]
        products: { keycloak: "25.0.6" }
        os: { name: rhel, release: "9.4", kernel: "5.14.0-427.13.1.el9_4" }
      stage:
        products: { keycloak: "26.0.1" }
  globex:
    environments:
      prod: { products: { gitlab-ce: "19.5.3" } }
```

One CLI with a kubeconfig context per cluster builds the whole file.
`stack merge` adds a tenant or environment the file doesn't have yet:

```sh
vulnwatch stack merge stack.yaml                                                # the local cluster
vulnwatch stack merge stack.yaml --context acme-prod  --tenant acme   --environment prod
vulnwatch stack merge stack.yaml --context acme-stage --tenant acme   --environment stage
vulnwatch stack merge stack.yaml --context globex     --tenant globex --environment prod
vulnwatch stack diff --context acme-prod --tenant acme --environment prod       # drift check
```

`stack discover --tenant acme --environment prod` writes a new file with the
stack nested under `tenants.acme.environments.prod`.

- **Same sections everywhere.** Each environment has `helm`, `products` and
  `os`. Defaults layer: stack.yaml, then the tenant's, then the
  environment's, then the product's own settings.
- **Fetched once.** Advisories are fetched once per product, however many
  tenants run it, and matched against each tenant's versions. Claude triages
  a finding once for all tenants that run the same version with the same
  exposure and criticality.
- **Named everywhere.** Findings, state, Slack messages, metrics, alerts and
  dashboards carry the tenant and environment; reports say `acme/prod
  keycloak`.
- **Slack routing.** A tenant or environment with its own `channel` gets its
  own run summary and P1 alerts there (in `alert_channel`, else the same
  channel), with a dashboard link that selects the tenant. The local stack and
  tenants without channels use `SLACK_CHANNEL` / `SLACK_ALERT_CHANNEL`, which
  also get the run's warning count. Every channel is told when a source
  failed (by name only).
- **Trivy is local.** Image findings belong to the local stack only. A
  tenant's kernel is watched from its `os` section, like the local one.
- **Compatible.** A stack.yaml without `tenants` is one tenant, `local/default`.
  State written before tenants existed stays valid for the local stack.
