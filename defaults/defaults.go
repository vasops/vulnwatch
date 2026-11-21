// Package defaults holds the default config.yaml and sources.yaml, built into
// the binary as the base layer under --app-config and --sources.
package defaults

import _ "embed"

//go:embed config.yaml
var Config []byte

//go:embed sources.yaml
var Sources []byte
