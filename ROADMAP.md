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
- **cvelistV5 names for the whole catalog:** products without them are
  invisible to that source.
- **NVD on demand:** ask NVD per CVE ID only, for records without usable
  versions, instead of sweeping every product's CPEs.

## Prioritisation

- **VEX export:** OpenVEX of "not affected" triage decisions, so Trivy in CI
  and trivy-operator stop reporting them.
- **Owners:** an `owner` per product, alerts routed to that team's channel.
- **SLAs:** maximum days open per priority, with alerts when exceeded.
- **Exploit signals:** public exploits (Metasploit, Nuclei templates) as a
  third signal next to KEV and EPSS.
- **Other models for triage:** providers other than Claude, local models
  included.

## Integrations

- **Tickets:** GitHub or GitLab issues, or Jira, opened and closed with the
  finding.
- **Upgrade pull requests:** propose the chart or image bump in the GitOps
  repository when the upgrade target is known (or hand it to Renovate).
- **Dependency-Track:** push the stack as an SBOM and use its audit workflow
  and UI; vulnwatch keeps the Slack summary.
- **DefectDojo:** export findings for teams that track SLAs and compliance there.
- **More outputs:** Microsoft Teams, generic webhook, email digest.
- **Grafana annotations:** mark new P1 findings on dashboards.

## Distribution

- **More platforms:** linux/arm64 images, and linux/arm64 and darwin/amd64
  binaries.
- **Build provenance:** SLSA provenance attestations for the image and the
  binaries, next to the cosign signatures.
- **Artifact Hub:** list the Helm chart there.
- **Easier install:** a Homebrew formula or an install script instead of a
  manual download.

## Operations

- **`vulnwatch explain <id>`:** everything known about one finding, with its
  sources, match and triage.
- **Catalog check in CI:** run `sources test` per product to catch moved
  repositories and CPEs.
- **Faster runs:** cache NVD and OSV responses between runs.
