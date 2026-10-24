package sbomreuse

import (
	"bytes"
	"encoding/json"
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// compatible preserves the entire Syft document in the same storage model used by
// local generation. The initial profile is for complete image inventories, not
// runtime-relevancy filtering. An empty image may legitimately have no packages.
func compatible(raw []byte, s subject, producer trust) (*v1beta1.SyftDocument, error) {
	var header struct {
		Schema struct {
			Version string `json:"version"`
		} `json:"schema"`
		Descriptor struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"descriptor"`
		Artifacts json.RawMessage `json:"artifacts"`
		Source    struct {
			Type     string `json:"type"`
			Metadata struct {
				ManifestDigest string `json:"manifestDigest"`
				ImageID        string `json:"imageID"`
				Manifest       []byte `json:"manifest"`
				Config         []byte `json:"config"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	if header.Schema.Version != "16.0.39" || header.Schema.Version != producer.SchemaVersion || header.Descriptor.Name != "syft" || header.Descriptor.Version != producer.SyftVersion {
		return nil, fmt.Errorf("unsupported Syft producer or schema")
	}
	if len(header.Artifacts) == 0 || string(header.Artifacts) == "null" {
		return nil, fmt.Errorf("inventory has no artifact array")
	}
	meta := header.Source.Metadata
	if header.Source.Type != "image" || meta.ManifestDigest != s.ref.DigestStr() || meta.ImageID != s.configDigest {
		return nil, fmt.Errorf("syft source identity mismatch")
	}
	mh, _, err := v1.SHA256(bytes.NewReader(meta.Manifest))
	if err != nil {
		return nil, err
	}
	ch, _, err := v1.SHA256(bytes.NewReader(meta.Config))
	if err != nil {
		return nil, err
	}
	if mh.String() != meta.ManifestDigest || ch.String() != s.configDigest {
		return nil, fmt.Errorf("syft source metadata digest mismatch")
	}
	var cfg v1.ConfigFile
	if err := json.Unmarshal(meta.Config, &cfg); err != nil {
		return nil, err
	}
	if !samePlatform(v1.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}, s.platform) {
		return nil, fmt.Errorf("syft source platform mismatch")
	}
	var doc v1beta1.SyftDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	ids := make(map[string]bool, len(doc.Artifacts))
	for _, pkg := range doc.Artifacts {
		if pkg.ID == "" || pkg.Name == "" || pkg.Type == "" || ids[pkg.ID] {
			return nil, fmt.Errorf("invalid or duplicate package record")
		}
		ids[pkg.ID] = true
	}
	return &doc, nil
}
