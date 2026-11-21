package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const newsPage1 = `<table><tbody>
<tr><td><a href="/security/vulnerabilities/RHSB-2026-017" hreflang="en">RHSB-2026-017 Remote Code Execution - Apache HTTP Server (CVE-2026-119618)</a></td></tr>
</tbody></table>`

const newsPage2 = `<table><tbody>
<tr><td><a href="/security/vulnerabilities/RHSB-2026-018" hreflang="en">RHSB-2026-018 Remote Code Execution - OpenJDK (CVE-2026-114938) - &quot;java4shell&quot;</a></td></tr>
<tr><td><a href="/security/vulnerabilities/RHSB-2026-017" hreflang="en">RHSB-2026-017 Remote Code Execution - Apache HTTP Server (CVE-2026-119618)</a></td></tr>
</tbody></table>`

// A feed read for the first time is only remembered; a later item is
// printed once, with the stack product its title names.
func TestNews(t *testing.T) {
	var page atomic.Value
	page.Store(newsPage1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(page.Load().(string)))
	}))
	defer srv.Close()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stack := write("stack.yaml", "products:\n  java: '21.0.x'\n")
	override := write("sources-override.yaml", "version: 1\nsources:\n  news:\n    enabled: true\n    feeds:\n      - {name: Red Hat, url: '"+srv.URL+"/security/vulnerabilities', format: rhsb}\n")
	env := map[string]string{
		"STACK_CONFIG":      stack,
		"STATE_DB":          filepath.Join(dir, "news.db"),
		"VULNWATCH_SOURCES": "../../defaults/sources.yaml," + override,
	}
	out, errOut, code := run(t, env, "news")
	if code != 0 || out != "" || !strings.Contains(errOut, "read for the first time") {
		t.Fatalf("first: exit %d\n%s\n%s", code, out, errOut)
	}
	page.Store(newsPage2)
	out, errOut, code = run(t, env, "news")
	if code != 0 {
		t.Fatalf("second: exit %d\n%s", code, errOut)
	}
	for _, want := range []string{
		`Red Hat · RHSB-2026-018 Remote Code Execution - OpenJDK (CVE-2026-114938) - "java4shell"`,
		srv.URL + "/security/vulnerabilities/RHSB-2026-018",
		"runs here: java (local/default)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "RHSB-2026-017") {
		t.Errorf("an item from the first read was printed:\n%s", out)
	}
	if out, _, _ = run(t, env, "news"); out != "" {
		t.Fatalf("third: printed again:\n%s", out)
	}
}

// --repost posts the newest items again, on the first read too.
func TestNewsRepost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(newsPage2))
	}))
	defer srv.Close()
	dir := t.TempDir()
	override := filepath.Join(dir, "sources-override.yaml")
	if err := os.WriteFile(override, []byte("version: 1\nsources:\n  news:\n    enabled: true\n    feeds:\n      - {name: Red Hat, url: '"+srv.URL+"/security/vulnerabilities', format: rhsb}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stack := filepath.Join(dir, "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  java: '21.0.x'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"STACK_CONFIG":      stack,
		"STATE_DB":          filepath.Join(dir, "news.db"),
		"VULNWATCH_SOURCES": "../../defaults/sources.yaml," + override,
	}
	for i := range 2 {
		out, errOut, code := run(t, env, "news", "--repost", "1")
		if code != 0 || !strings.Contains(out, "RHSB-2026-018") || strings.Contains(out, "RHSB-2026-017") {
			t.Fatalf("run %d: exit %d\n%s\n%s", i, code, out, errOut)
		}
	}
	if out, _, _ := run(t, env, "news"); out != "" {
		t.Fatalf("without --repost: printed:\n%s", out)
	}
	if _, errOut, code := run(t, env, "news", "--repost", "-1"); code == 0 || !strings.Contains(errOut, "--repost") {
		t.Fatalf("negative: exit %d: %s", code, errOut)
	}
}

func TestNewsDisabled(t *testing.T) {
	override := filepath.Join(t.TempDir(), "sources-override.yaml")
	if err := os.WriteFile(override, []byte("version: 1\nsources:\n  news:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut, code := run(t, map[string]string{"VULNWATCH_SOURCES": "../../defaults/sources.yaml," + override}, "news")
	if code == 0 || !strings.Contains(errOut, "sources.news is disabled") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
