package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/vasops/vulnwatch/internal/config"
	"github.com/vasops/vulnwatch/internal/sandbox"
)

// Landlock modes (--landlock, env VULNWATCH_LANDLOCK).
const (
	landlockOff        = "false"   // no sandbox
	landlockBestEffort = "true"    // the sandbox where the kernel has Landlock
	landlockRequire    = "require" // no Landlock in the kernel fails the run
)

// applyLandlock is sandbox.Apply; tests replace it so they don't restrict
// the test process.
var applyLandlock = sandbox.Apply

// parseLandlock maps a --landlock value to its mode (empty: best effort).
func parseLandlock(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "1", "true", "yes":
		return landlockBestEffort, nil
	case "0", "false", "no":
		return landlockOff, nil
	case landlockRequire:
		return landlockRequire, nil
	}
	return "", fmt.Errorf("--landlock (env %s): want true, false or require, got %q", envLandlock, s)
}

// restrict applies Landlock for a run: read the config files' directories
// and the system files, write the state and report directories and the
// temp dir, connect only to the ports of the configured URLs.
func (a *app) restrict(cfg *config.Config, of outputFlags) error {
	mode, err := parseLandlock(a.landlock)
	if err != nil {
		return err
	}
	if mode == landlockOff {
		a.log.Info("landlock off (--landlock=false)")
		return nil
	}
	read := append([]string{}, sandbox.System...)
	for _, p := range append(append([]string{a.configPath}, a.appConfig...), a.sourcesPaths...) {
		read = append(read, sandbox.DirOf(p))
	}
	write := []string{sandbox.DirOf(a.stateDB), os.TempDir(), sandbox.DirOf(of.htmlPath), sandbox.DirOf(of.jsonPath), sandbox.DirOf(of.metricsFile)}
	cfgJSON, _ := json.Marshal(cfg)
	stack, _ := os.ReadFile(a.configPath) //nolint:gosec // the stack file the operator names
	ports := sandbox.Ports(a.getenv, cfgJSON, stack)
	abi, err := applyLandlock(sandbox.Spec{ReadDirs: read, WriteDirs: write, TCPPorts: ports})
	if err != nil {
		return err
	}
	if abi == 0 {
		if mode == landlockRequire {
			return errors.New("landlock: not available on this system (kernel, seccomp profile or not Linux) and --landlock=require; " +
				"--landlock=true runs unrestricted instead")
		}
		a.log.Warn("landlock not available on this system; running unrestricted (--landlock=require fails the run instead)")
		return nil
	}
	a.log.Info("landlock applied", landlockLogArgs(abi, ports)...)
	return nil
}

// landlockLogArgs names the TCP ports only when the kernel enforces them.
func landlockLogArgs(abi int, ports []uint16) []any {
	if !sandbox.TCPEnforced(abi) {
		return []any{"abi", abi, "tcp_enforced", false}
	}
	return []any{"abi", abi, "tcp_enforced", true, "tcp_ports", ports}
}
