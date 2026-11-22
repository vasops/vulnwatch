package discover

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"

	"github.com/vasops/vulnwatch/internal/helmchart"
)

// maxRelease caps a decompressed Helm release (Kubernetes Secrets are at
// most 1 MiB compressed).
const maxRelease = 32 << 20

// helmRelease is the part of a Helm 3 release record vulnwatch needs.
// Subcharts are not stored in the record, only the parent chart.
type helmRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Version   int    `json:"version"`
	Chart     struct {
		Metadata struct {
			Name       string `json:"name"`
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"metadata"`
		Values map[string]any `json:"values"`
	} `json:"chart"`
	Config map[string]any `json:"config"` // the values given at install/upgrade
}

// decodeRelease decodes a sh.helm.release.v1 Secret's "release" value:
// base64 of the gzipped JSON record.
func decodeRelease(data []byte) (*helmRelease, error) {
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(raw) > 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		if raw, err = io.ReadAll(io.LimitReader(zr, maxRelease)); err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
	}
	var r helmRelease
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if r.Name == "" || r.Chart.Metadata.Name == "" {
		return nil, fmt.Errorf("not a Helm release record")
	}
	return &r, nil
}

// chart returns the release's chart with the values it was installed with.
func (r *helmRelease) chart() *helmchart.Chart {
	m := r.Chart.Metadata
	return &helmchart.Chart{Name: m.Name, Version: m.Version, AppVersion: m.AppVersion, Values: mergeValues(r.Chart.Values, r.Config)}
}

// mergeValues layers over onto base like Helm does (maps merge key by key).
func mergeValues(base, over map[string]any) map[string]any {
	out := maps.Clone(base)
	if out == nil {
		out = map[string]any{}
	}
	for k, v := range over {
		if om, ok := v.(map[string]any); ok {
			if bm, ok := out[k].(map[string]any); ok {
				out[k] = mergeValues(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}
