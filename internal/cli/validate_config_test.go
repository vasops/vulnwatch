package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/vasops/vulnwatch/internal/catalog"
	"github.com/vasops/vulnwatch/internal/config"
)

func TestSelectorLinesCVEList(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sources.CVEList.Enabled = true
	p := catalog.Product{Name: "httpd", Entry: config.CatalogEntry{
		CVEList: []config.CVEListName{{Vendor: "Apache Software Foundation", Product: "Apache HTTP Server"}},
		NVD:     []string{"cpe:2.3:a:apache:http_server"},
	}}
	want := "cvelist:             Apache Software Foundation / Apache HTTP Server, the nvd CPEs"
	if lines := selectorLines(cfg, p); !slices.Contains(lines, want) {
		t.Fatalf("lines: %q", lines)
	}
}

func TestValidateConfigTokenWarnings(t *testing.T) {
	stack := filepath.Join(t.TempDir(), "stack.yaml")
	if err := os.WriteFile(stack, []byte("products:\n  keycloak: '26.7.0'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		env    map[string]string
		want   []string
		absent []string
	}{
		{"no tokens", map[string]string{},
			[]string{"warning: GITHUB_TOKEN is not set", "warning: NVD_API_KEY is not set: NVD requests are spaced 6s apart instead of 1s"}, nil},
		{"GitHub token only", map[string]string{"GITHUB_TOKEN": "x"},
			[]string{"NVD_API_KEY is not set"}, []string{"GITHUB_TOKEN"}},
		{"both tokens", map[string]string{"GITHUB_TOKEN": "x", "NVD_API_KEY": "y"},
			nil, []string{"warning:"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errOut, code := run(t, tt.env, "validate-config", "--config", stack)
			if code != 0 {
				t.Fatalf("warnings must not fail validation: exit %d: %s", code, errOut)
			}
			for _, s := range tt.want {
				if !strings.Contains(errOut, s) {
					t.Errorf("missing %q in:\n%s", s, errOut)
				}
			}
			for _, s := range tt.absent {
				if strings.Contains(errOut, s) {
					t.Errorf("unexpected %q in:\n%s", s, errOut)
				}
			}
		})
	}
}
