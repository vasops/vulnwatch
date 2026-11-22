package helmchart

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// helmChartLayer is the media type of the chart archive in an OCI artifact.
const helmChartLayer = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"

// pullOCIRemote downloads the chart layer of an OCI artifact anonymously
// (public registries; the registry's token flow is handled by the library).
func (f *Fetcher) pullOCIRemote(ctx context.Context, ref string) ([]byte, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
		remote.WithTransport(f.client.HTTPClient().Transport),
		remote.WithUserAgent(f.client.UserAgent()),
	}
	desc, err := remote.Get(r, opts...)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(desc.Manifest, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	for _, l := range manifest.Layers {
		if l.MediaType != helmChartLayer {
			continue
		}
		layer, err := remote.Layer(r.Context().Digest(l.Digest), opts...)
		if err != nil {
			return nil, err
		}
		rc, err := layer.Compressed()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		b, err := io.ReadAll(io.LimitReader(rc, f.maxSize+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > f.maxSize {
			return nil, fmt.Errorf("chart layer exceeds %d bytes", f.maxSize)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%s is not a Helm chart (no %s layer)", ref, helmChartLayer)
}
