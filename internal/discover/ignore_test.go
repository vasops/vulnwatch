package discover

import (
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/imageref"
)

// Images of common Kubernetes add-ons and of RKE2's bundled software (the
// tags are examples): each must be a product, ignored, or (own images)
// still listed.
func TestObserveCatalogAndIgnoreList(t *testing.T) {
	cfg := loadConfig(t)
	cfg.IgnoreImages["own"] = []string{"registry.example.com/platform/**", "ghcr.io/example-org/*"}
	images := map[string]string{ // image -> product, "-" ignored, "?" still listed
		"docker.io/rancher/hardened-etcd:v3.6.4-k3s1-build20260310":           "etcd v3.6.4",
		"docker.io/rancher/hardened-coredns:v1.14.3-build20260310":            "coredns v1.14.3",
		"ghcr.io/dexidp/dex:v2.45.0":                                          "dex v2.45.0",
		"ecr-public.aws.com/docker/library/redis:8.4.0-alpine":                "redis 8.4.0",
		"docker.io/nginxinc/nginx-unprivileged:1.28-alpine":                   "nginx 1.28",
		"ghcr.io/cloudnative-pg/pgbouncer:1.24.0":                             "pgbouncer 1.24.0",
		"mirror.gcr.io/aquasec/trivy:0.70.0":                                  "trivy 0.70.0",
		"docker.io/rancher/hardened-snapshot-controller:v8.3.0-build20260310": "external-snapshotter v8.3.0",
		"docker.io/rancher/nginx-ingress-controller:v1.13.3-hardened1":        "ingress-nginx v1.13.3",
		"docker.io/rancher/hardened-traefik:v3.6.2-build20260310":             "traefik v3.6.2",
		"docker.io/rancher/hardened-calico:v3.31.0-build20260310":             "calico v3.31.0",
		"docker.io/rancher/hardened-flannel:v0.27.4-build20260310":            "flannel v0.27.4",
		"docker.io/rancher/hardened-k8s-metrics-server:v0.8.0-build20260310":  "-",
		"docker.io/rancher/hardened-dns-node-cache:1.26.4-build20260310":      "-",
		"docker.io/rancher/hardened-cni-plugins:v1.8.0-build20260310":         "-",
		"docker.io/rancher/mirrored-cilium-hubble-ui-backend:v0.13.2":         "-",
		"docker.io/rancher/mirrored-cilium-certgen:v0.4.5":                    "-",
		"mirror.gcr.io/aquasec/trivy-operator:0.30.0":                         "-",
		"quay.io/brancz/kube-rbac-proxy:v0.19.1":                              "-",
		"quay.io/kiwigrid/k8s-sidecar:2.1.2":                                  "-",
		"quay.io/prometheus-operator/prometheus-config-reloader:v0.85.0":      "-",
		"registry.k8s.io/sig-storage/csi-attacher:v4.10.0":                    "-",
		"registry.k8s.io/sig-storage/livenessprobe:v2.17.0":                   "-",
		"registry.example.com/platform/images/agent-base:v0.1.0":              "-",
		"ghcr.io/example-org/agent:0.10.0":                                    "-",
		"ghcr.io/someone-else/tool:1.0":                                       "?",
	}
	var ws []Workload
	for img := range images {
		ws = append(ws, Workload{Namespace: "ns", Owner: "Deployment/x", Image: imageref.Parse(img)})
	}
	obs, unmapped, ignored := observe(cfg, ws)
	got := map[string]string{}
	for _, o := range obs {
		got[o.w.Image.String()] = o.product + " " + o.version
	}
	for _, n := range unmapped {
		got[n.What] = "?"
	}
	wantIgnored := 0
	for img, want := range images {
		key := imageref.Parse(img).String()
		if want == "-" {
			wantIgnored++
			if _, listed := got[key]; listed {
				t.Errorf("%s: want ignored, got %q", img, got[key])
			}
			continue
		}
		if got[key] != want {
			t.Errorf("%s: got %q, want %q", img, got[key], want)
		}
	}
	if ignored != wantIgnored {
		t.Errorf("ignored %d, want %d", ignored, wantIgnored)
	}

	var b strings.Builder
	WriteNotes(&b, &Result{Unmapped: unmapped, Ignored: ignored})
	if !strings.Contains(b.String(), "someone-else/tool") || !strings.Contains(b.String(), "running images on the ignore_images list") {
		t.Errorf("notes:\n%s", b.String())
	}
}
