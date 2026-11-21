# Roadmap

Ideas, not commitments. vulnwatch stays a small "what to patch today" tool;
anything that turns it into a vulnerability management platform belongs in a
tool built for that (see Integrations).

## Inventory

- **Drift check in the CronJob:** run `stack diff` in-cluster (read-only
  ClusterRole) and report unwatched products and stale versions in Slack.
- **SBOM export:** `stack discover --format cyclonedx` for audits and other tools.
- **Products inside images:** read trivy-operator's SBOMReports to find
  bundled software (e.g. a Keycloak jar in another image).
- **Remote Trivy:** image findings for tenants' clusters (today Trivy only
  reads the cluster vulnwatch runs in).

## Sources

- **Kubernetes components from Trivy:** ClusterVulnerabilityReports as
  confirmation for `kubernetes` and `rke2`.
- **GitLab:** gitlab-org/advisories-community as structured data instead of RSS.
- **HashiCorp bulletins:** Vault advisories with a keyword filter.
- **End of life:** endoflife.date warnings before a product, chart or OS
  release goes out of support.
- **Vendor CSAF feeds:** Red Hat, SUSE, Cisco and others for products without
  OSV data.
- **Full node coverage:** optional package scan of the nodes (Vuls or Trivy
  rootfs) for more than the kernel.
- **NVD on demand:** every run counts the findings only cvelistV5 or only
  NVD found. Once a month of counts shows cvelistV5 finds what NVD finds,
  drop NVD's CPE sweep and ask it per CVE ID only, for records without
  usable versions.

## Prioritisation

- **VEX export:** OpenVEX of "not affected" triage decisions, so Trivy in CI
  and trivy-operator stop reporting them.
- **Owners:** an `owner` per product, alerts routed to that team's channel.
- **SLAs:** maximum days open per priority, with alerts when exceeded.
- **Exploit signals:** public exploits (Metasploit, Nuclei templates) as a
  third signal next to KEV and EPSS.

## Integrations

- **Tickets:** GitLab issues or Jira, opened and closed with the finding.
- **Upgrade merge requests:** propose the chart or image bump in the Argo CD
  repository when the upgrade target is known (or hand it to Renovate).
- **Dependency-Track:** push the stack as an SBOM and use its audit workflow
  and UI; vulnwatch keeps the Slack summary.
- **DefectDojo:** export findings for teams that track SLAs and compliance there.
- **More outputs:** Microsoft Teams, generic webhook, email digest.
- **Grafana annotations:** mark new P1 findings on dashboards.

## Security

- **Signature enforcement:** an admission controller (Kyverno `verifyImages`
  or sigstore policy-controller) that rejects vulnwatch images without a valid
  signature, with the image pinned by digest in the Argo CD values.
- **Pushgateway lock-down:** a NetworkPolicy that admits only vulnwatch and
  Prometheus, so nobody else in the cluster can overwrite or delete its
  metrics.
- **Pod Security Standard:** label the vulnwatch namespace
  `pod-security.kubernetes.io/enforce: restricted`.
- **Runtime enforcement:** Tetragon killing any `execve` in the pod, and a
  seccomp profile recorded with Security Profiles Operator.

## Operations

- **`vulnwatch explain <id>`:** everything known about one finding, with its
  sources, match and triage.
- **Catalog check in CI:** run `sources test` per product to catch moved
  repositories and CPEs.
- **Faster runs:** cache NVD and OSV responses between runs.
