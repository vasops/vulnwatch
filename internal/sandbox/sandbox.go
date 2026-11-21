// Package sandbox restricts the running process with Landlock (Linux): after
// startup vulnwatch can only read the files it needs, write its state and
// reports, and connect to the TCP ports of the services it calls. Code
// execution in the process (a parser bug, a malicious dependency) then
// can't read other files, write elsewhere or reach other services.
//
// It is best effort: on kernels without Landlock, and on other systems, it
// restricts nothing, and newer Landlock features (network, UDP) apply only
// where the kernel has them. Apply returns ABI 0 when nothing was
// restricted; --landlock=require turns that into a failed run.
package sandbox

import (
	"cmp"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Spec is what the process may still do.
type Spec struct {
	ReadDirs  []string // read (and list) everything below
	WriteDirs []string // read and write everything below
	TCPPorts  []uint16 // connect(2) to these remote ports
}

// System is what every run needs: name resolution and CA certificates
// (/etc), the Kubernetes service account token (in-cluster sources), time
// zones, and the cgroup files the Go runtime reads for GOMAXPROCS.
var System = []string{
	"/etc",
	"/var/run/secrets/kubernetes.io/serviceaccount",
	"/usr/share/zoneinfo",
	"/proc/self",
	"/sys/fs/cgroup",
}

// TCPEnforced says whether Landlock ABI abi restricts TCP connects (ABI 4,
// Linux 6.7). Below it BestEffort drops the TCPPorts rules.
func TCPEnforced(abi int) bool { return abi >= 4 }

// Apply restricts the process (every thread) and returns the Landlock ABI
// version the kernel offers (0: not available, nothing restricted).
func Apply(s Spec) (abi int, err error) {
	if v, err := llsys.LandlockGetABIVersion(); err == nil && v > 0 {
		abi = v
	}
	rules := []landlock.Rule{
		landlock.RODirs(clean(s.ReadDirs)...).IgnoreIfMissing(),
		landlock.RWDirs(clean(s.WriteDirs)...).IgnoreIfMissing(),
		// DNS: UDP (Landlock V10+ restricts UDP too) and TCP fallback.
		landlock.ConnectSendUDP(53),
		landlock.BindUDP(0),
	}
	for _, p := range slices.Compact(slices.Sorted(slices.Values(s.TCPPorts))) {
		rules = append(rules, landlock.ConnectTCP(p))
	}
	if err := landlock.V11.BestEffort().Restrict(rules...); err != nil {
		return abi, fmt.Errorf("landlock: %w", err)
	}
	return abi, nil
}

// clean drops empty paths and resolves the rest; duplicates are fine.
func clean(paths []string) []string {
	var out []string
	for _, p := range paths {
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		out = append(out, p)
	}
	return out
}

// DirOf is the directory a file is read or written in ("" for "-" or "").
func DirOf(path string) string {
	if path == "" || path == "-" {
		return ""
	}
	return filepath.Dir(path)
}

var urlRe = regexp.MustCompile(`(?i)\b(https?|oci)://[^\s"'<>\\]+`)

// Ports returns the TCP ports of every URL in the given texts (config and
// stack as JSON or YAML), 443 for HTTPS and OCI, 80 for plain HTTP, plus the
// DNS TCP port, the Kubernetes API port and the ports of proxies in env.
func Ports(getenv func(string) string, texts ...[]byte) []uint16 {
	ports := []uint16{443, 53}
	add := func(raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		def := "443"
		if u.Scheme == "http" {
			def = "80"
		}
		if p, err := strconv.ParseUint(cmp.Or(u.Port(), def), 10, 16); err == nil && p > 0 {
			ports = append(ports, uint16(p)) //nolint:gosec // ParseUint with bitSize 16 bounds it
		}
	}
	for _, t := range texts {
		for _, m := range urlRe.FindAll(t, -1) {
			add(string(m))
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if v := getenv(k); v != "" {
			add(v)
		}
	}
	if p, err := strconv.ParseUint(getenv("KUBERNETES_SERVICE_PORT"), 10, 16); err == nil && p > 0 {
		ports = append(ports, uint16(p)) //nolint:gosec // ParseUint with bitSize 16 bounds it
	}
	return slices.Compact(slices.Sorted(slices.Values(ports)))
}
