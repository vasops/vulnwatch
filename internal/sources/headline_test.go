package sources

import "testing"

func TestHeadline(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"containerd", "containerd is an open source container runtime. A bug was found in containerd's CRI implementation where a user can exhaust memory on the host. This bug has been fixed in 1.6.12.",
			"A bug was found in containerd's CRI implementation where a user can exhaust memory on the host."},
		{"redis", "Redis is an open source (BSD licensed), in-memory data structure store, used as a database, cache, and message broker. An authenticated user can use a specially crafted Lua script to trigger a heap overflow.",
			"An authenticated user can use a specially crafted Lua script to trigger a heap overflow."},
		{"redis newer wording", "Redis is an in-memory database that persists on disk. On startup, Redis begins listening on a Unix socket before adjusting its permissions.",
			"On startup, Redis begins listening on a Unix socket before adjusting its permissions."},
		{"mariadb", "MariaDB is a community-developed, commercially supported fork of the MySQL relational database management system. MariaDB Server 10.6 before 10.6.19 crashes on a crafted SELECT.",
			"MariaDB Server 10.6 before 10.6.19 crashes on a crafted SELECT."},
		{"open-source wording", "Argo CD is a declarative, GitOps continuous delivery tool for Kubernetes. Argo CD versions before 2.9.3 leak repository credentials.",
			"Argo CD versions before 2.9.3 leak repository credentials."},
		{"no product intro", "A flaw was found in Keycloak. An attacker can bypass the login.", "A flaw was found in Keycloak."},
		{"intro that names the flaw", "Keycloak is an identity server that is vulnerable to session fixation. Upgrade.", "Keycloak is an identity server that is vulnerable to session fixation."},
		{"there is a", "There is a heap overflow in libfoo. It is fixed in 1.2.", "There is a heap overflow in libfoo."},
		{"intro only", "Redis is an in-memory database that persists on disk.", "Redis is an in-memory database that persists on disk."},
		{"wrapped lines", "Redis is an in-memory database\nthat persists on disk. A crafted\ncommand crashes the server.", "A crafted command crashes the server."},
		{"intro paragraph", "Redis is an in-memory database that persists on disk\n\nAuthenticated users can crash the server", "Authenticated users can crash the server"},
		{"markdown heading", "### Impact\nAn attacker can read other tenants' data.\n\n### Patches\nFixed in 2.0.", "An attacker can read other tenants' data."},
		{"no sentence end", "Denial of service in the parser", "Denial of service in the parser"},
		{"empty", "  ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Headline(tt.in); got != tt.want {
				t.Fatalf("got  %q\nwant %q", got, tt.want)
			}
		})
	}
}
