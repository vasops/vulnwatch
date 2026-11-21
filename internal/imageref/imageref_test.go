package imageref

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Ref
	}{
		{"postgres:17.4", Ref{"docker.io", "library/postgres", "17.4", ""}},
		{"bitnami/keycloak:20.0.3-debian-11-r0", Ref{"docker.io", "bitnami/keycloak", "20.0.3-debian-11-r0", ""}},
		{"quay.io/keycloak/keycloak:26.7.0", Ref{"quay.io", "keycloak/keycloak", "26.7.0", ""}},
		{"ghcr.io/x/y:v1@sha256:abc", Ref{"ghcr.io", "x/y", "v1", "sha256:abc"}},
		{"localhost:5000/app", Ref{"localhost:5000", "app", "", ""}},
		{"docker.io/library/nginx@sha256:abc", Ref{"docker.io", "library/nginx", "", "sha256:abc"}},
		{"index.docker.io/Grafana/grafana:12.0.0", Ref{"docker.io", "grafana/grafana", "12.0.0", ""}},
	}
	for _, c := range cases {
		if got := Parse(c.in); got != c.want {
			t.Errorf("Parse(%q) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

func TestMatches(t *testing.T) {
	cases := []struct {
		image, pattern string
		want           bool
	}{
		{"postgres:17", "postgres", true},
		{"docker.io/library/postgres:17", "postgres", true},
		{"registry.example.com/dockerhub/library/postgres:17", "postgres", true},
		{"mirror.gcr.io/library/postgres:17", "docker.io/library/postgres", true},
		{"ghcr.io/cloudnative-pg/postgresql:17.4", "postgres", false},
		{"quay.io/keycloak/keycloak:26", "quay.io/keycloak/keycloak", true},
		{"quay.io/notkeycloak/keycloak:26", "quay.io/keycloak/keycloak", false},
	}
	for _, c := range cases {
		if got := Parse(c.image).Matches(Parse(c.pattern)); got != c.want {
			t.Errorf("%s matches %s = %v, want %v", c.image, c.pattern, got, c.want)
		}
	}
}

func TestVersion(t *testing.T) {
	cases := map[string]string{
		"quay.io/prometheus/prometheus:v3.9.1-distroless":          "v3.9.1",
		"ghcr.io/cloudnative-pg/postgresql:17.4-7-bullseye":        "17.4",
		"ghcr.io/berriai/litellm:main-v1.80.0-stable":              "v1.80.0",
		"quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z":         "RELEASE.2025-04-22T22-12-26Z",
		"rancher/hardened-kubernetes:v1.34.2-rke2r2-build20260101": "v1.34.2",
		"nvcr.io/nvidia/k8s/container-toolkit:v1.17.8-ubuntu20.04": "v1.17.8",
		"gitlab/gitlab-ce:19.5.1-ce.0":                             "19.5.1",
		"example/app:2.0.0-rc.1":                                   "2.0.0-rc.1",
		"renovate/renovate:43":                                     "43",
		"nginx:latest":                                             "",
		"nginx@sha256:abc":                                         "",
		"ghcr.io/x/y:sha-0a1b2c3":                                  "",
	}
	for in, want := range cases {
		if got := Parse(in).Version(); got != want {
			t.Errorf("Version(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesPattern(t *testing.T) {
	cases := []struct {
		image, pattern string
		want           bool
	}{
		{"registry.k8s.io/sig-storage/csi-attacher:v4.10.0", "sig-storage/csi-*", true},
		{"registry.k8s.io/sig-storage/livenessprobe:v2.17.0", "sig-storage/csi-*", false},
		{"quay.io/kiwigrid/k8s-sidecar:2.1.2", "kiwigrid/k8s-sidecar", true},
		{"docker.io/kiwigrid/k8s-sidecar:2.5.0", "kiwigrid/k8s-sidecar", true},
		{"mirror.example.com/dockerhub/kiwigrid/k8s-sidecar:1", "kiwigrid/k8s-sidecar", true},
		{"docker.io/rancher/mirrored-cilium-hubble-ui-backend:v0.13.2", "rancher/mirrored-cilium-hubble-ui*", true},
		{"registry.example.com/platform/images/agent-base:v0.1.0", "registry.example.com/platform/**", true},
		{"registry.example.com/platform/images/portal:v0.1.0", "registry.example.com/platform/**", true},
		{"registry.example.com/other/x:1", "registry.example.com/platform/**", false},
		{"ghcr.io/platform/x:1", "registry.example.com/platform/**", false},
		{"ghcr.io/example-org/agent:0.10.0", "ghcr.io/example-org/*", true},
		{"ghcr.io/example-org/agent:0.10.0", "ghcr.io/example-org", false},
		{"docker.io/library/redis:8", "redis", true},
		{"quay.io/keycloak/keycloak:26", "", false},
	}
	for _, c := range cases {
		if got := Parse(c.image).MatchesPattern(c.pattern); got != c.want {
			t.Errorf("%s ~ %q = %v, want %v", c.image, c.pattern, got, c.want)
		}
	}
}
