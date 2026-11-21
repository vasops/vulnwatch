package ostracker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/httpx"
	"github.com/vasops/vulnwatch/internal/sources"
)

type obj = map[string]any

func affected(eco, pkg, fixed string, extra obj) obj {
	events := []obj{{"introduced": "0"}}
	if fixed != "" {
		events = append(events, obj{"fixed": fixed})
	}
	a := obj{"package": obj{"ecosystem": eco, "name": pkg}, "ranges": []obj{{"type": "ECOSYSTEM", "events": events}}}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func server(t *testing.T, byVersion map[string][]obj) (*httpx.Client, string, *[]obj) {
	t.Helper()
	var queries []obj
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q obj
		json.NewDecoder(r.Body).Decode(&q)
		queries = append(queries, q)
		json.NewEncoder(w).Encode(obj{"vulns": byVersion[q["version"].(string)]})
	}))
	t.Cleanup(srv.Close)
	c := httpx.New(config.HTTP{Timeout: config.Duration(5 * time.Second), MaxResponseBytes: 1 << 20}, "test", nil)
	return c, srv.URL, &queries
}

func TestDebian(t *testing.T) {
	recs := []obj{
		{"id": "DEBIAN-CVE-2026-46300", "upstream": []string{"CVE-2026-46300"}, "summary": "net: use after free", "modified": "2026-11-01T00:00:00Z",
			"affected": []obj{affected("Debian:12", "linux", "6.1.150-1", nil), affected("Debian:13", "linux", "6.12.62-1", obj{"ecosystem_specific": obj{"urgency": "high"}})}},
		{"id": "DEBIAN-CVE-2004-0230", "upstream": []string{"CVE-2004-0230"}, "summary": "TCP window",
			"affected": []obj{affected("Debian:13", "linux", "", obj{"ecosystem_specific": obj{"urgency": "unimportant"}})}},
	}
	c, url, queries := server(t, map[string][]obj{"6.12.48": recs, "6.12.62": nil})
	o := &config.StackOS{Name: "debian", Release: "13", Kernel: "6.12.48 || 6.12.62"}
	fs, err := New(url, c).Fetch(context.Background(), sources.Selector{Product: "debian-13-kernel", OS: o, Versions: []string{"6.12.48", "6.12.62"}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 2 || (*queries)[0]["package"].(obj)["ecosystem"] != "Debian:13" || (*queries)[0]["package"].(obj)["name"] != "linux" {
		t.Fatalf("queries: %v", *queries)
	}
	if len(fs) != 1 {
		t.Fatalf("only the CVE with a fix in Debian 13: %+v", fs)
	}
	f := fs[0]
	if f.ID != "CVE-2026-46300" || f.Severity != "high" || !slices.Equal(f.Fixed, []string{"6.12.62-1"}) || f.Sources[0] != Name ||
		f.References[0] != "https://security-tracker.debian.org/tracker/CVE-2026-46300" || f.Modified.IsZero() {
		t.Fatalf("finding: %+v", f)
	}
}

func TestRockyAdvisoriesPerCVE(t *testing.T) {
	recs := []obj{
		{"id": "RLSA-2024:2758", "upstream": []string{"CVE-2023-6240", "CVE-2024-25742"}, "summary": "Important: kernel security update",
			"references": []obj{{"url": "https://errata.rockylinux.org/RLSA-2024:2758"}},
			"affected":   []obj{affected("Rocky Linux:9", "kernel", "0:5.14.0-427.16.1.el9_4", nil)}},
		{"id": "RLSA-2024:3000", "upstream": []string{"CVE-2024-25742"}, "summary": "Moderate: kernel security update",
			"affected": []obj{affected("Rocky Linux:9", "kernel", "0:5.14.0-427.18.1.el9_4", nil)}},
		{"id": "RLBA-2024:1", "summary": "kernel bug fix update", "affected": []obj{affected("Rocky Linux:9", "kernel", "0:5.14.0-427.17.1.el9_4", nil)}},
	}
	c, url, queries := server(t, map[string][]obj{"5.14.0-427.13.1.el9_4": recs})
	o := &config.StackOS{Name: "rocky", Release: "9.4", Kernel: "5.14.0-427.13.1.el9_4"}
	fs, err := New(url, c).Fetch(context.Background(), sources.Selector{Product: "debian-13-kernel", OS: o, Versions: []string{o.Kernel}}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if q := (*queries)[0]["package"].(obj); q["ecosystem"] != "Rocky Linux:9" || q["name"] != "kernel" {
		t.Fatalf("query: %v", q)
	}
	if len(fs) != 2 {
		t.Fatalf("one finding per CVE, bug fix advisory skipped: %+v", fs)
	}
	f := fs[1]
	if f.ID != "CVE-2024-25742" || f.Severity != "high" || !slices.Equal(f.Fixed, []string{"5.14.0-427.16.1.el9_4", "5.14.0-427.18.1.el9_4"}) ||
		f.Title != "RLSA-2024:2758: Important: kernel security update" || f.References[0] != "https://errata.rockylinux.org/RLSA-2024:2758" {
		t.Fatalf("merged finding: %+v", f)
	}
}

func TestEcosystems(t *testing.T) {
	cases := map[[2]string]string{
		{"debian", "13"}:          "Debian:13",
		{"ubuntu", "24.04"}:       "Ubuntu:24.04:LTS",
		{"ubuntu", "24.10"}:       "Ubuntu:24.10",
		{"rhel", "9.4"}:           "Red Hat:enterprise_linux:9::baseos",
		{"rocky", "9.4"}:          "Rocky Linux:9",
		{"almalinux", "8"}:        "AlmaLinux:8",
		{"sles", "15-sp6"}:        "SUSE:Linux Enterprise Module for Basesystem 15 SP6",
		{"opensuse-leap", "15.6"}: "openSUSE:Leap 15.6",
	}
	for in, want := range cases {
		if got := Distros[in[0]].ecosystem(in[1]); got != want {
			t.Errorf("%v = %q, want %q", in, got, want)
		}
	}
	for _, n := range config.OSNames {
		if _, ok := Distros[n]; !ok {
			t.Errorf("config.OSNames has %q, ostracker doesn't", n)
		}
	}
}

func TestKernelTitle(t *testing.T) {
	title, desc := describe(record{Details: "In the Linux kernel, the following vulnerability has been resolved:\n\nnetfilter: bridge: make ebt_snat ARP rewrite writable\n\nThe ebtables SNAT target keeps..."})
	if title != "netfilter: bridge: make ebt_snat ARP rewrite writable" || !strings.HasPrefix(desc, "In the Linux kernel") {
		t.Fatalf("title %q desc %q", title, desc)
	}
	if title, _ := describe(record{Summary: "Important: kernel security update", Details: "long"}); title != "Important: kernel security update" {
		t.Fatalf("advisory title %q", title)
	}
}
