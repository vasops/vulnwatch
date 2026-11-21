// Command vulnwatch reports new security advisories for the software we operate.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/vasops/vulnwatch/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}
