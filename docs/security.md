# Security

vulnwatch reads untrusted data all day (advisories, chart archives, the
model's answers), so it is built to assume something goes wrong. The full
threat model is in [`threat-model.md`](threat-model.md).

- **Triage can't be talked down.** Advisory text is data, not instructions,
  for Claude. Exploited findings (KEV, a public exploit, or SSVC "active" on an important
  product) and affected ones with CVSS ≥ 9 stay relevant and at least P2
  whatever the model answers. Any other finding our version is affected by
  and the rules rate P1 or P2 stays listed: Claude may lower it to P3, not
  hide it. Every verdict below the rule-based priority is written to the
  audit log.
- **Sandboxed with Landlock** (Linux): after startup `run` and `bootstrap`
  can only read `/etc`, the config directories and the service account
  token, write the state, temp and report directories, and connect to the
  TCP ports of the configured URLs (kernel 6.7+). Without Landlock in the
  kernel it runs unrestricted and warns in the log; `--landlock=require`
  (`VULNWATCH_LANDLOCK=require`, the chart's default) fails the run instead,
  and `--landlock=false` turns it off. `make landlock-selftest` proves the
  denials in a container, and CI runs the same test.
- **Bounded input:** response size limits and timeouts on every request, one
  unpack budget per Helm chart (nested archives included), TLS 1.2 or newer,
  and a source that panics becomes a warning instead of a failed run.
- **Small image:** static binary, distroless, non-root, read-only root
  filesystem, no capabilities, seccomp, Go soft memory limit at 90% of the
  container's limit. The chart has NetworkPolicy (HTTPS egress only, or by
  host name with Cilium) and `runtimeClassName` for gVisor or Kata.
- **Supply chain, checked in CI:** golangci-lint with gosec, depguard (no
  `unsafe`, `os/exec`, `text/template`, `math/rand`, pprof) and forbidigo (no
  default HTTP client or mux); `go test -race`; `go mod verify` and
  `-mod=readonly`; govulncheck (blocking, and daily); capslock, which fails
  when the binary gains a capability (`make capslock-baseline` after review);
  fuzzing of every parser in a scheduled workflow; Trivy on the sources and
  on the pushed image (HIGH/CRITICAL with a fix block the chart release);
  Renovate; a CycloneDX SBOM per image; keyless cosign signatures on the
  release image, its SBOM attestation and the chart.

```sh
make security            # govulncheck + capslock
make fuzz FUZZTIME=30s   # every fuzz target
make landlock-selftest   # Landlock denials, in Docker
```

Release images and charts are signed by the `ci` workflow of this repository
(GitHub's OIDC identity, no key to distribute):

```sh
cosign verify ghcr.io/vasops/vulnwatch:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/vasops/vulnwatch/\.github/workflows/ci\.yml@refs/tags/v'
```

The same flags verify the chart (`ghcr.io/vasops/charts/vulnwatch:<version>`)
and the image's SBOM attestation (`cosign verify-attestation --type cyclonedx`).
Release binaries are covered by the signed `checksums.txt`:

```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/vasops/vulnwatch/\.github/workflows/ci\.yml@refs/tags/v'
sha256sum --check --ignore-missing checksums.txt
```

To report a vulnerability in vulnwatch itself, see [`SECURITY.md`](../SECURITY.md).
