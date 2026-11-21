//go:build linux

package sandbox

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestEnforced restricts the test process itself, so it runs only on
// request (VULNWATCH_LANDLOCK_SELFTEST=1, e.g. in a container) and alone.
func TestEnforced(t *testing.T) {
	if os.Getenv("VULNWATCH_LANDLOCK_SELFTEST") != "1" {
		t.Skip("set VULNWATCH_LANDLOCK_SELFTEST=1 to restrict this process")
	}
	// Not t.TempDir: its cleanup runs after the sandbox and is denied too.
	allowed, err := os.MkdirTemp("", "allowed")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := os.MkdirTemp("", "denied")
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(denied, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:gosec // a local listener the sandbox must not reach
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	abi, err := Apply(Spec{ReadDirs: System, WriteDirs: []string{allowed}, TCPPorts: []uint16{443}})
	if err != nil || abi == 0 {
		t.Fatalf("landlock not applied: abi %d, %v", abi, err)
	}
	if err := os.WriteFile(filepath.Join(allowed, "ok"), []byte("x"), 0o600); err != nil {
		t.Errorf("writing the allowed dir: %v", err)
	}
	if _, err := os.ReadFile(secret); !errors.Is(err, syscall.EACCES) {
		t.Errorf("reading outside the allowed dirs: want EACCES, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(denied, "new"), []byte("x"), 0o600); !errors.Is(err, syscall.EACCES) {
		t.Errorf("writing outside the allowed dirs: want EACCES, got %v", err)
	}
	if abi >= 4 {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err == nil {
			c.Close()
			t.Errorf("connecting to a port that isn't allowed must fail")
		}
	}
	t.Logf("landlock ABI %d enforced", abi)
}
