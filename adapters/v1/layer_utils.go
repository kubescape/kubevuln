package v1

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/source"
)

// parseLayersFromConfigAndManifest parses RawConfig and RawManifest to populate Layers
func parseLayersFromConfigAndManifest(meta *source.ImageMetadata) (*source.ImageMetadata, error) {
	type manifestLayer struct {
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		MediaType string `json:"mediaType"`
	}
	type manifest struct {
		Layers []manifestLayer `json:"layers"`
	}
	type config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	var m manifest
	var c config
	if err := json.Unmarshal(meta.RawManifest, &m); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}
	if err := json.Unmarshal(meta.RawConfig, &c); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	layers := make([]source.LayerMetadata, 0, len(m.Layers))
	for i, l := range m.Layers {
		digest := l.Digest
		if digest == "" && i < len(c.RootFS.DiffIDs) {
			digest = c.RootFS.DiffIDs[i]
		}
		layers = append(layers, source.LayerMetadata{
			Digest: digest,
			Size:   l.Size,
		})
	}
	meta.Layers = layers
	return meta, nil
}
