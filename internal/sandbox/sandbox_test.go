package sandbox

import (
	"slices"
	"testing"
)

func TestPorts(t *testing.T) {
	env := map[string]string{"HTTPS_PROXY": "http://proxy.local:3128", "KUBERNETES_SERVICE_PORT": "6443"}
	cfg := []byte(`{"pushgateway_url":"http://pushgateway.monitoring:9091","base_url":"https://api.osv.dev/v1","x":"http://plain.example/feed"}`)
	stack := []byte("helm:\n  - { repo: oci://registry.example:5000/charts, chart: x }\n  - { repo: https://charts.example:8443/stable }\n")
	got := Ports(func(k string) string { return env[k] }, cfg, stack)
	want := []uint16{53, 80, 443, 3128, 5000, 6443, 8443, 9091}
	if !slices.Equal(got, want) {
		t.Fatalf("ports %v, want %v", got, want)
	}
}

func TestDirOf(t *testing.T) {
	if DirOf("-") != "" || DirOf("") != "" || DirOf("/data/report.html") != "/data" {
		t.Fatal(DirOf("-"), DirOf(""), DirOf("/data/report.html"))
	}
}
