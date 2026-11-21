package imageref

import "testing"

// Image references come from every pod in the cluster.
func FuzzParse(f *testing.F) {
	for _, s := range []string{"quay.io/keycloak/keycloak:26.7.0", "docker.io/library/redis:8@sha256:abc", "localhost:5000/x", "registry/x:RELEASE.2024-10-02T17-50-41Z", "x:v1.17.8-ubuntu20.04", "", ":", "@", "a//b:"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := Parse(s)
		_ = r.Version()
		_ = r.Matches(Parse("quay.io/keycloak/keycloak"))
	})
}
