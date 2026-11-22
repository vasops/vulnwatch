# Deployment

**Kubernetes:** use the Helm chart, see [`charts/vulnwatch`](../charts/vulnwatch/README.md).

**Docker:**

```sh
docker run --rm --read-only -v $PWD/examples:/config:ro \
  -v vulnwatch-state:/data -e GITHUB_TOKEN -e ANTHROPIC_API_KEY \
  ghcr.io/vasops/vulnwatch:<version> run
```

`make docker` builds the same image locally as `vulnwatch:<version>`.

The image is distroless and runs as nonroot. It reads `/config/stack.yaml`,
uses the built-in defaults (set `VULNWATCH_CONFIG` / `VULNWATCH_SOURCES` to
layer overrides) and keeps the state in `/data`.

Release binaries for linux/amd64 and darwin/arm64 are attached to every
[GitHub release](https://github.com/vasops/vulnwatch/releases), with the
image's SBOM and checksums.
