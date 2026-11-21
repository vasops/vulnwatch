package discover

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/helmchart"
	"github.com/vasops/vulnwatch/internal/imageref"
	"github.com/vasops/vulnwatch/internal/kube"
)

type obj = map[string]any

func list(items ...obj) obj { return obj{"metadata": obj{}, "items": items} }

func podObj(ns, name, owner, phase string, labels map[string]string, images ...string) obj {
	var cs []obj
	for _, i := range images {
		cs = append(cs, obj{"image": i})
	}
	kind, oname, _ := strings.Cut(owner, "/")
	return obj{
		"metadata": obj{"namespace": ns, "name": name, "labels": labels, "ownerReferences": []obj{{"kind": kind, "name": oname}}},
		"spec":     obj{"containers": cs},
		"status":   obj{"phase": phase},
	}
}

func helmSecret(t *testing.T, ns, name string, rev int, chart obj, config obj) obj {
	t.Helper()
	b, _ := json.Marshal(obj{"name": name, "namespace": ns, "version": rev, "chart": chart, "config": config})
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write(b)
	zw.Close()
	return obj{
		"metadata": obj{"namespace": ns, "name": fmt.Sprintf("sh.helm.release.v1.%s.v%d", name, rev)},
		"data":     obj{"release": []byte(base64.StdEncoding.EncodeToString(gz.Bytes()))},
	}
}

func fakeCluster(t *testing.T) *kube.Client {
	t.Helper()
	routes := map[string]any{
		"/version": obj{"gitVersion": "v1.34.2+rke2r1"},
		"/api/v1/nodes": list(
			obj{"metadata": obj{"name": "n1"}, "status": obj{"nodeInfo": obj{"kubeletVersion": "v1.34.2+rke2r1", "containerRuntimeVersion": "containerd://2.0.6-k3s1",
				"osImage": "Debian GNU/Linux 13 (trixie)", "kernelVersion": "6.12.62+deb13.1-cloud-amd64"}}},
			obj{"metadata": obj{"name": "n2"}, "status": obj{"nodeInfo": obj{"kubeletVersion": "v1.34.2+rke2r1", "containerRuntimeVersion": "containerd://2.0.6-k3s1",
				"osImage": "Debian GNU/Linux 13 (trixie)", "kernelVersion": "6.12.48+deb13-cloud-amd64"}}},
		),
		"/api/v1/pods": list(
			podObj("kube-system", "cilium-x", "DaemonSet/cilium", "Running", nil, "quay.io/cilium/cilium:v1.18.2@sha256:abc"),
			podObj("minio", "minio-0", "StatefulSet/minio", "Running", map[string]string{"app": "minio"}, "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"),
			podObj("monitoring", "prometheus-0", "StatefulSet/prometheus", "Running", nil, "quay.io/prometheus/prometheus:v3.9.1-distroless"),
			podObj("keycloak", "keycloak-0", "StatefulSet/keycloak", "Running", map[string]string{"app": "keycloak"}, "quay.io/keycloak/keycloak:26.7.0"),
			podObj("keycloak", "pg-1", "Cluster/pg", "Running", nil, "ghcr.io/cloudnative-pg/postgresql:17.4-7-bullseye"),
			podObj("default", "foo-7d9f-abc", "ReplicaSet/foo-7d9f", "Running", nil, "ghcr.io/acme/foo:1.2.3"),
			podObj("default", "foo-7d9f-def", "ReplicaSet/foo-7d9f", "Running", nil, "ghcr.io/acme/foo:1.2.3"),
			podObj("default", "web", "ReplicaSet/web-55f", "Running", nil, "grafana/grafana:latest"),
			podObj("default", "old-job", "Job/migrate", "Succeeded", nil, "quay.io/keycloak/keycloak:20.0.0"),
		),
		"/apis/batch/v1/cronjobs": list(obj{
			"metadata": obj{"namespace": "renovate", "name": "renovate"},
			"spec":     obj{"jobTemplate": obj{"spec": obj{"template": obj{"spec": obj{"containers": []obj{{"image": "ghcr.io/renovatebot/renovate:43.1.0"}}}}}}},
		}),
		"/api/v1/services": list(
			obj{"metadata": obj{"namespace": "keycloak", "name": "keycloak"}, "spec": obj{"type": "ClusterIP", "selector": obj{"app": "keycloak"}}},
			obj{"metadata": obj{"namespace": "minio", "name": "minio"}, "spec": obj{"type": "LoadBalancer", "selector": obj{"app": "minio"}}},
		),
		"/apis/gateway.networking.k8s.io/v1/httproutes": list(obj{
			"metadata": obj{"namespace": "keycloak", "name": "keycloak"},
			"spec":     obj{"hostnames": []string{"auth.example.com"}, "rules": []obj{{"backendRefs": []obj{{"name": "keycloak"}}}}},
		}),
		"/apis/argoproj.io/v1alpha1/applications": list(
			obj{"metadata": obj{"name": "minio"}, "spec": obj{
				"source":      obj{"repoURL": "https://charts.min.io/", "chart": "minio", "targetRevision": "5.4.0"},
				"destination": obj{"server": "https://kubernetes.default.svc", "namespace": "minio"}}},
			obj{"metadata": obj{"name": "prometheus-stack"}, "spec": obj{
				"sources": []obj{
					{"repoURL": "https://prometheus-community.github.io/helm-charts", "chart": "kube-prometheus-stack", "targetRevision": "84.1.0"},
					{"repoURL": "https://git.example.com/apps.git", "ref": "values"},
				},
				"destination": obj{"server": "https://kubernetes.default.svc", "namespace": "monitoring"}}},
			obj{"metadata": obj{"name": "vulnwatch"}, "spec": obj{
				"source":      obj{"repoURL": "registry.example.com/charts", "chart": "vulnwatch", "targetRevision": "0.2.0"},
				"destination": obj{"name": "in-cluster", "namespace": "vulnwatch"}}},
			obj{"metadata": obj{"name": "remote"}, "spec": obj{
				"source":      obj{"repoURL": "https://charts.min.io/", "chart": "minio", "targetRevision": "5.0.0"},
				"destination": obj{"server": "https://other.example.com", "namespace": "minio"}}},
		),
		"/api/v1/secrets": list(
			helmSecret(t, "cert-manager", "cert-manager", 1, obj{"metadata": obj{"name": "cert-manager", "version": "v1.20.0", "appVersion": "v1.20.0"}}, nil),
			helmSecret(t, "cert-manager", "cert-manager", 2, obj{"metadata": obj{"name": "cert-manager", "version": "v1.20.5", "appVersion": "v1.20.5"}}, nil),
			helmSecret(t, "minio", "minio", 1, obj{"metadata": obj{"name": "minio", "version": "5.0.0", "appVersion": "RELEASE.2023-01-01T00-00-00Z"}}, nil),
		),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/api/v1/secrets" && r.URL.Query().Get("labelSelector") != "owner=helm,status=deployed" {
			t.Errorf("secrets selector = %q", r.URL.Query().Get("labelSelector"))
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return kube.NewForTest(srv.URL, srv.Client())
}

type fakeCharts map[string]*helmchart.Chart

func (f fakeCharts) Fetch(_ context.Context, r config.HelmRelease) (*helmchart.Chart, error) {
	if c, ok := f[r.Chart+" "+r.Version]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("helm chart %s %s: not found", r.Chart, r.Version)
}

var charts = fakeCharts{
	"minio 5.4.0": {Name: "minio", Version: "5.4.0", Values: map[string]any{
		"image":   map[string]any{"tag": "RELEASE.2024-10-02T17-50-41Z"},
		"mcImage": map[string]any{"tag": "RELEASE.2024-09-16T17-43-14Z"},
	}},
	"kube-prometheus-stack 84.1.0": {Name: "kube-prometheus-stack", Version: "84.1.0", AppVersion: "v0.88.1", Values: map[string]any{
		"prometheus":   map[string]any{"prometheusSpec": map[string]any{"image": map[string]any{"tag": "v3.9.1"}}},
		"alertmanager": map[string]any{"alertmanagerSpec": map[string]any{"image": map[string]any{"tag": "v0.30.1"}}},
	}, Subcharts: map[string]*helmchart.Chart{
		"grafana":                  {AppVersion: "13.0.5"},
		"kube-state-metrics":       {AppVersion: "2.17.0"},
		"prometheus-node-exporter": {AppVersion: "1.10.2"},
	}},
}

func loadConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{ConfigPaths: []string{"../../defaults/config.yaml"}, Paths: []string{"../../defaults/sources.yaml"}, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDiscover(t *testing.T) {
	ctx := context.Background()
	cfg := loadConfig(t)
	inv, err := Collect(ctx, fakeCluster(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Build(ctx, cfg, inv, charts, 2)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(res, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	t.Log("\n" + got)

	for _, want := range []string{
		"from context test on 2026-11-04",
		"\ngenerated_at: \"2026-11-04\" # inventory date; stack merge updates it\n",
		"  - {repo: 'https://prometheus-community.github.io/helm-charts', chart: kube-prometheus-stack, version: 84.1.0} # argocd app prometheus-stack\n",
		"  - repo: https://charts.min.io/ # argocd app minio\n" +
			"    chart: minio\n" +
			"    version: 5.4.0\n" +
			"    versions:\n" +
			"      minio: \"RELEASE.2025-04-22T22-12-26Z\" # chart default RELEASE.2024-10-02T17-50-41Z\n" +
			"    exposure: internet # LoadBalancer service minio\n",
		"  cert-manager: \"v1.20.5\" # helm release cert-manager/cert-manager (cert-manager v1.20.5)\n",
		"  cilium: \"v1.18.2\" # quay.io/cilium/cilium:v1.18.2 (kube-system)\n",
		"  containerd: \"2.0.6\" # container runtime on the nodes\n",
		"  keycloak: # quay.io/keycloak/keycloak:26.7.0 (keycloak)\n" +
			"    version: \"26.7.0\"\n" +
			"    exposure: internet # HTTPRoute auth.example.com\n",
		"  kubernetes: \"1.34.2\" # API server and 2 kubelet(s)\n",
		"  postgresql: \"17.4\"",
		"  renovate: \"43.1.0\" # ghcr.io/renovatebot/renovate:43.1.0 (renovate)\n",
		"  rke2: \"v1.34.2+rke2r1\"",
		"#   ghcr.io/acme/foo:1.2.3  (default/Deployment/foo)\n",
		"# The nodes' OS: its kernel is watched as debian-13-kernel (sources.os).\nos:\n  name: debian\n  release: \"13\"\n  kernel: \"6.12.48 || 6.12.62\" # the nodes run different kernels\n  criticality: high # every workload runs on the nodes\n",
		"#   docker.io/grafana/grafana:latest  (default/Deployment/web)\n",
		"#   argocd app vulnwatch: vulnwatch 0.2.0 (oci://registry.example.com/charts)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks:\n%s", want)
		}
	}
	for _, unwanted := range []string{"20.0.0", "prometheus:", "5.0.0", "2023-01-01"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("output contains %q", unwanted)
		}
	}
	if len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "other clusters") ||
		res.Warnings[1] != "helm release minio/minio (minio 5.0.0) is managed by argocd app minio; its release record is stale, skipped" {
		t.Errorf("warnings = %q", res.Warnings)
	}

	stack, err := config.ParseStack(b)
	if err != nil {
		t.Fatalf("generated stack: %v", err)
	}
	if !stack.GeneratedAt.Equal(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("generated_at = %v", stack.GeneratedAt)
	}
	// In a tenant's environment, generated_at dates that environment.
	b, err = RenderScope(res, time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), []string{"tenants", "acme", "environments", "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if scoped, err := config.ParseStack(b); err != nil || !scoped.GeneratedAt.IsZero() ||
		scoped.Tenants["acme"].Environments["prod"].GeneratedAt.Format(time.DateOnly) != "2026-11-04" {
		t.Errorf("tenant environment's generated_at: %v\n%s", err, b)
	}
	if _, err := catalog.Resolve(cfg, stack); err != nil {
		t.Fatalf("generated stack: %v", err)
	}

	// Observed: chart products (with overrides) plus the products section.
	for p, want := range map[string]string{"debian-13-kernel": "6.12.48 || 6.12.62", "minio": "RELEASE.2025-04-22T22-12-26Z", "minio-mc": "RELEASE.2024-09-16T17-43-14Z", "prometheus": "v3.9.1", "grafana": "13.0.5", "keycloak": "26.7.0"} {
		if got := strings.Join(res.Observed[p], " || "); got != want {
			t.Errorf("observed %s = %q, want %q", p, got, want)
		}
	}
}

func TestDiscoverChartFetchFails(t *testing.T) {
	ctx := context.Background()
	inv := &Inventory{
		Context: "test", ServerVersion: "v1.34.2",
		Apps:      []App{{Name: "minio", Namespace: "minio", Repo: "https://charts.min.io/", Chart: "minio", Version: "9.9.9"}},
		Workloads: []Workload{{Namespace: "minio", Owner: "StatefulSet/minio", Image: imageRef("quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"), Pods: 1}},
	}
	res, err := Build(ctx, loadConfig(t), inv, charts, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Helm) != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "kept without comparing images") {
		t.Fatalf("helm = %d, warnings = %q", len(res.Helm), res.Warnings)
	}
	// The image is not compared with the chart, so it is listed as a product too.
	if got := res.Observed["minio"]; len(got) != 1 || got[0] != "RELEASE.2025-04-22T22-12-26Z" {
		t.Errorf("observed minio = %q", got)
	}
}

func TestDiff(t *testing.T) {
	cfg := loadConfig(t)
	stack, err := config.ParseStack([]byte(`
products:
  kubernetes: ">=1.33.0"
  keycloak: "26.7.0"
  postgresql: "17.4"
  grafana: "13.0.5 || 13.2.4"
  cilium: "1.18.2 || 1.18.0"
  go: "1.26.x"
`))
	if err != nil {
		t.Fatal(err)
	}
	declared, err := catalog.Resolve(cfg, stack)
	if err != nil {
		t.Fatal(err)
	}
	rows := Diff(declared, map[string][]string{
		"kubernetes": {"1.34.2"},
		"keycloak":   {"26.7.0", "26.8.0"},
		"postgresql": {"17.4"},
		"cilium":     {"v1.18.2"},
		"grafana":    {"13.0.5", "13.2.4"},
		"vault":      {"2.0.3"},
	})
	var got []string
	for _, r := range rows {
		got = append(got, r.Product+"="+r.Status)
	}
	want := "keycloak=drift vault=not in stack cilium=stale go=not in cluster grafana=ok kubernetes=ok postgresql=ok"
	if strings.Join(got, " ") != want {
		t.Errorf("diff = %s\nwant %s", strings.Join(got, " "), want)
	}
}

func TestDecodeReleaseMergesValues(t *testing.T) {
	s := helmSecret(t, "ns", "vault", 3,
		obj{"metadata": obj{"name": "vault", "version": "0.33.0", "appVersion": "2.0.3"}, "values": obj{"server": obj{"image": obj{"tag": "2.0.3", "repository": "hashicorp/vault"}}}},
		obj{"server": obj{"image": obj{"tag": "2.0.5"}}})
	r, err := decodeRelease(s["data"].(obj)["release"].([]byte))
	if err != nil {
		t.Fatal(err)
	}
	img := r.chart().Values["server"].(map[string]any)["image"].(map[string]any)
	if img["tag"] != "2.0.5" || img["repository"] != "hashicorp/vault" {
		t.Errorf("merged image values = %v", img)
	}
	if _, err := decodeRelease([]byte(base64.StdEncoding.EncodeToString([]byte(`{"foo":1}`)))); err == nil {
		t.Error("want an error for a non-release record")
	}
}

func imageRef(s string) imageref.Ref { return imageref.Parse(s) }

func TestNodeOS(t *testing.T) {
	cases := []struct {
		nodes []Node
		want  string
		notes int
	}{
		{[]Node{{Name: "a", OSImage: "Ubuntu 24.04.3 LTS", Kernel: "6.8.0-71-generic"}, {Name: "b", OSImage: "Ubuntu 24.04.3 LTS", Kernel: "6.8.0-79-generic"}},
			"ubuntu 24.04 6.8.0-71 || 6.8.0-79 linux", 0},
		{[]Node{{Name: "a", OSImage: "Ubuntu 22.04.5 LTS", Kernel: "6.8.0-1020-aws"}}, "ubuntu 22.04 6.8.0-1020 linux-aws", 0},
		{[]Node{{Name: "a", OSImage: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-28-cloud-amd64"}}, "", 1},
		{[]Node{{Name: "a", OSImage: "Rocky Linux 9.4 (Blue Onyx)", Kernel: "5.14.0-427.13.1.el9_4.x86_64"}}, "rocky 9.4 5.14.0-427.13.1.el9_4 linux", 0},
		{[]Node{{Name: "a", OSImage: "Red Hat Enterprise Linux 9.4 (Plow)", Kernel: "5.14.0-427.13.1.el9_4.aarch64"}}, "rhel 9.4 5.14.0-427.13.1.el9_4 linux", 0},
		{[]Node{{Name: "a", OSImage: "SUSE Linux Enterprise Server 15 SP6", Kernel: "6.4.0-150600.23.17-default"}}, "sles 15 SP6 6.4.0-150600.23.17.1 linux", 0},
		{[]Node{{Name: "a", OSImage: "openSUSE Leap 15.6", Kernel: "6.4.0-150600.23.17-azure"}}, "opensuse-leap 15.6 6.4.0-150600.23.17.1 kernel-azure", 0},
		{[]Node{{Name: "a", OSImage: "Red Hat Enterprise Linux CoreOS 418.94", Kernel: "5.14.0-427.13.1.el9_4.x86_64"}}, "", 1},
		{[]Node{{Name: "a", OSImage: "Flatcar Container Linux 4152.2.3", Kernel: "6.6.95-flatcar"}}, "", 1},
		{[]Node{{Name: "a", OSImage: "Debian GNU/Linux 13 (trixie)", Kernel: "6.12.48+deb13-cloud-amd64"},
			{Name: "b", OSImage: "Ubuntu 24.04.3 LTS", Kernel: "6.8.0-71-generic"},
			{Name: "c", OSImage: "Debian GNU/Linux 13 (trixie)", Kernel: "6.12.48+deb13-cloud-amd64"}}, "debian 13 6.12.48 linux", 1},
	}
	for i, c := range cases {
		o, notes := nodeOS(c.nodes)
		got := ""
		if o != nil {
			got = o.Name + " " + o.Release + " " + o.Kernel + " " + cmp.Or(o.KernelPackage, "linux")
		}
		if got != c.want || len(notes) != c.notes {
			t.Errorf("case %d: got %q notes %v, want %q with %d notes", i, got, notes, c.want, c.notes)
		}
	}
}
