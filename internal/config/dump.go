package config

import (
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// SecretStatus reports, per secret env var named in the config, whether it is set.
// Values are never included.
func (c *Config) SecretStatus(getenv func(string) string) map[string]string {
	if getenv == nil {
		getenv = os.Getenv
	}
	names := []string{
		c.Sources.GHSA.TokenEnv, c.Sources.NVD.APIKeyEnv, c.Sources.CVEList.TokenEnv, c.Triage.APIKeyEnv,
		c.Outputs.Slack.TokenEnv, c.Outputs.PagerDuty.RoutingKeyEnv,
	}
	for _, env := range c.Outputs.Webhook.HeadersEnv {
		names = append(names, env)
	}
	out := map[string]string{}
	for _, n := range names {
		if n == "" {
			continue
		}
		if getenv(n) != "" {
			out[n] = "set (redacted)"
		} else {
			out[n] = "unset"
		}
	}
	return out
}

// Dump renders the effective configuration as YAML. The config itself holds
// only env var names, never secret values; their set/unset status is appended.
func (c *Config) Dump(getenv func(string) string) ([]byte, error) {
	doc := struct {
		*Config `yaml:",inline"`
		Secrets map[string]string `yaml:"secrets"`
	}{c, c.SecretStatus(getenv)}
	return yaml.Marshal(doc)
}

// SortedKeys is a small helper for deterministic map iteration.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
