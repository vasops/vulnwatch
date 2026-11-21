FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
# VERSION is optional: without it the binary reports version/version.go.
# TARGETOS and TARGETARCH come from the build platform (BuildKit, buildah).
ARG TARGETOS=linux TARGETARCH VERSION= COMMIT=unknown DATE=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -mod=readonly -trimpath \
      -ldflags "-s -w \
        ${VERSION:+-X github.com/vasops/vulnwatch/version.Version=${VERSION}} \
        -X github.com/vasops/vulnwatch/version.Commit=${COMMIT} \
        -X github.com/vasops/vulnwatch/version.Date=${DATE}" \
      -o /out/vulnwatch ./cmd/vulnwatch

# distroless/static ships CA certificates and runs as uid 65532.
# Compatible with readOnlyRootFilesystem: state and reports go to mounted volumes.
FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source="https://github.com/vasops/vulnwatch" \
      org.opencontainers.image.description="Daily report of new vulnerabilities for the software you run" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/vulnwatch /usr/local/bin/vulnwatch
WORKDIR /data
USER nonroot:nonroot
# config.yaml and sources.yaml are built in; VULNWATCH_CONFIG / VULNWATCH_SOURCES layer overrides.
ENV STACK_CONFIG=/config/stack.yaml \
    STATE_DB=/data/vulnwatch.db
ENTRYPOINT ["/usr/local/bin/vulnwatch"]
CMD ["run", "--output", "stdout"]
