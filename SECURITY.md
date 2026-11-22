# Security policy

## Reporting a vulnerability

Report vulnerabilities in vulnwatch privately, through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/vasops/vulnwatch/security/advisories/new). Do not open a
public issue for them.

Include what you can of:

- the version (`vulnwatch version`) or image digest,
- how to reproduce it: the command, the configuration and, when an advisory
  or a feed triggers it, that input,
- what an attacker gains.

You get an answer in the advisory thread. A fix is released as a new version
and the advisory is published with it.

## Supported versions

Only the latest release gets fixes.

## What counts

vulnwatch reads untrusted data (advisories, chart archives, the model's
answers) and holds API tokens, so these are in scope:

- advisory or feed content that hides a finding, lowers its priority below
  the rule-based floor or changes what is posted to Slack,
- input that crashes or stalls a run beyond the documented limits,
- anything that leaks tokens or the inventory (stack, tenants, registries),
- a way around the Landlock sandbox or the chart's restrictions.

The threat model is in [`docs/threat-model.md`](docs/threat-model.md).

Wrong or missing advisory data (a product without a source, a version range
that doesn't match) is a bug, not a vulnerability: open an issue.
