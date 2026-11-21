package cli

import (
	"runtime/debug"
	"strconv"
)

const envMemoryLimit = "VULNWATCH_MEMORY_LIMIT"

// applyMemoryLimit sets the Go soft memory limit to 90% of the container's
// memory limit (VULNWATCH_MEMORY_LIMIT in bytes, from the downward API), so
// the GC works harder before the kernel kills the pod. An explicit
// GOMEMLIMIT wins.
func (a *app) applyMemoryLimit() {
	if a.getenv("GOMEMLIMIT") != "" {
		return
	}
	n, err := strconv.ParseInt(a.getenv(envMemoryLimit), 10, 64)
	if err != nil || n <= 0 {
		return
	}
	limit := n / 10 * 9
	debug.SetMemoryLimit(limit)
	a.log.Debug("memory limit set", "container_limit", n, "go_soft_limit", limit)
}
