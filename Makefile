BINARY        := vulnwatch
PKG           := github.com/vasops/vulnwatch
# The version lives in version/version.go; builds add commit and date.
VERSION       ?= $(shell sed -n 's/^[[:space:]]*Version *= *"\(.*\)"/\1/p' version/version.go)
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE          ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS       := -s -w -X $(PKG)/version.Version=$(VERSION) -X $(PKG)/version.Commit=$(COMMIT) -X $(PKG)/version.Date=$(DATE)
GOLANGCI      ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
GOVULNCHECK   ?= go run golang.org/x/vuln/cmd/govulncheck@v1.9.0
CAPSLOCK      ?= go run github.com/google/capslock/cmd/capslock@v0.3.4
# The capability baseline is computed for the release build: linux/amd64,
# without cgo (CGO_ENABLED=0, as the Makefile sets for capslock).
CAPSLOCK_ARGS := -packages ./cmd/vulnwatch -goos linux -goarch amd64 -granularity package
CAPS_BASELINE := docs/capslock-baseline.json
FUZZTIME      ?= 60s
IMAGE         ?= vulnwatch:$(VERSION)
PLATFORM      ?= linux/amd64
DOCKER        ?= docker

.PHONY: all lint test build run-dry docker chart-sync chart-check chart-lint version-check clean \
	vulncheck capslock capslock-baseline fuzz security landlock-selftest triage-eval

all: lint test build

# Security checks CI runs as blocking jobs.
security: vulncheck capslock

# Known vulnerabilities in code vulnwatch actually calls.
vulncheck:
	$(GOVULNCHECK) ./...

# Fails when the binary gains a capability (exec, network, files, unsafe,
# ...) the baseline doesn't have; a dependency update can add one.
capslock:
	CGO_ENABLED=0 $(CAPSLOCK) $(CAPSLOCK_ARGS) -output compare $(CAPS_BASELINE)

# After reviewing a new capability: record it.
capslock-baseline:
	CGO_ENABLED=0 $(CAPSLOCK) $(CAPSLOCK_ARGS) -output json > $(CAPS_BASELINE)

# Every fuzz target for FUZZTIME each (the seeds also run in make test).
fuzz:
	go test -run='^$$' -fuzz='^FuzzMatch$$' -fuzztime=$(FUZZTIME) ./internal/match
	go test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/imageref
	go test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/helmchart
	go test -run='^$$' -fuzz='^FuzzParseStack$$' -fuzztime=$(FUZZTIME) ./internal/config
	go test -run='^$$' -fuzz='^FuzzValidate$$' -fuzztime=$(FUZZTIME) ./internal/triage

# Proves Landlock denies what it should, in a Linux container (it restricts
# the test process itself, so it doesn't run in make test).
landlock-selftest:
	GOOS=linux CGO_ENABLED=0 go test -c -o bin/sandbox.test ./internal/sandbox
	$(DOCKER) run --rm --user 65532:65532 -e VULNWATCH_LANDLOCK_SELFTEST=1 -v $(CURDIR)/bin:/t:ro alpine:3.22 \
		/t/sandbox.test -test.run TestEnforced -test.v

# Claude triage regression set against the real API (ANTHROPIC_API_KEY;
# CLAUDE_MODEL and CLAUDE_EFFORT as in a run): run it before changing the
# model, the effort or the prompt. Skips without the key.
triage-eval:
	go test -tags triageeval -run '^TestTriageEval$$' -count=1 -v ./internal/triage

lint:
	go vet ./...
	$(GOLANGCI) run ./...

test:
	go mod verify
	go test -race -mod=readonly ./...

build:
	CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/vulnwatch

# Dry run against the example stack: no state writes, no Slack.
run-dry: build
	./bin/$(BINARY) run --dry-run --config examples/stack.yaml --app-config defaults/config.yaml --sources defaults/sources.yaml --state-db ./vulnwatch.db

docker:
	$(DOCKER) build --platform $(PLATFORM) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t $(IMAGE) .

CHART := charts/vulnwatch

# The chart ships copies of the example config and sources files.
chart-sync:
	cp defaults/config.yaml $(CHART)/files/config.yaml
	cp defaults/sources.yaml $(CHART)/files/sources.yaml

chart-check:
	@diff -q defaults/config.yaml $(CHART)/files/config.yaml && diff -q defaults/sources.yaml $(CHART)/files/sources.yaml \
		|| (echo "chart files out of date: run make chart-sync" && exit 1)

chart-lint: chart-check
	helm lint $(CHART) -f $(CHART)/ci/full-values.yaml
	helm lint $(CHART) -f $(CHART)/ci/existing-stack-values.yaml
	helm template ci $(CHART) -f $(CHART)/ci/full-values.yaml >/dev/null
	helm template ci $(CHART) -f $(CHART)/ci/existing-stack-values.yaml >/dev/null
	helm lint $(CHART) -f $(CHART)/ci/cilium-values.yaml
	sh $(CHART)/ci/check-cilium-egress.sh

# The chart's appVersion must match version/version.go (without the v).
version-check:
	@grep -q '^appVersion: "$(VERSION:v%=%)"$$' $(CHART)/Chart.yaml \
		|| (echo "charts/vulnwatch/Chart.yaml appVersion != $(VERSION) from version/version.go" && exit 1)

clean:
	rm -rf bin
