package sbomreuse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const ArtifactType = "application/vnd.in-toto+json"
const EnvelopeMediaType = "application/vnd.dsse.envelope.v1+json"

type attestationManifest struct {
	v1.Manifest
	ArtifactType string `json:"artifactType"`
}

type attachment struct {
	envelope []byte
	digest   string
}

func (c *registryClient) discover(s subject, policy *CompiledPolicy) (attachment, error) {
	idx, err := remote.Referrers(s.ref, c.opts...)
	if err != nil {
		return attachment{}, err
	}
	manifest, err := idx.IndexManifest()
	if err != nil {
		return attachment{}, err
	}
	if len(manifest.Manifests) > policy.maxCandidates {
		return attachment{}, fmt.Errorf("referrers candidate limit exceeded")
	}
	var candidates []v1.Descriptor
	for _, d := range manifest.Manifests {
		if d.ArtifactType == ArtifactType {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) != 1 {
		return attachment{}, fmt.Errorf("expected exactly one attestation candidate")
	}
	d := candidates[0]
	if d.Size <= 0 || d.Size > policy.maxBytes {
		return attachment{}, fmt.Errorf("attestation manifest exceeds size limit")
	}
	artifact, err := remote.Get(s.ref.Context().Digest(d.Digest.String()), c.opts...)
	if err != nil {
		return attachment{}, err
	}
	h, size, err := v1.SHA256(bytes.NewReader(artifact.Manifest))
	if err != nil {
		return attachment{}, err
	}
	if h != d.Digest || size != d.Size {
		return attachment{}, fmt.Errorf("attestation manifest digest or size mismatch")
	}
	var m attestationManifest
	if err := json.Unmarshal(artifact.Manifest, &m); err != nil {
		return attachment{}, err
	}
	if m.SchemaVersion != 2 || m.ArtifactType != ArtifactType || m.Subject == nil || m.Subject.Digest != s.descriptor.Digest || m.Subject.Size != s.descriptor.Size || m.Subject.MediaType != s.descriptor.MediaType {
		return attachment{}, fmt.Errorf("attestation subject mismatch")
	}
	if len(m.Layers) != 1 || string(m.Layers[0].MediaType) != EnvelopeMediaType || len(m.Layers[0].URLs) > 0 {
		return attachment{}, fmt.Errorf("unsupported attestation envelope layout")
	}
	blob := m.Layers[0]
	if blob.Size <= 0 || blob.Size > policy.maxBytes {
		return attachment{}, fmt.Errorf("attestation envelope exceeds size limit")
	}
	layer, err := remote.Layer(s.ref.Context().Digest(blob.Digest.String()), c.opts...)
	if err != nil {
		return attachment{}, err
	}
	r, err := layer.Compressed()
	if err != nil {
		return attachment{}, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, policy.maxBytes+1))
	if err != nil {
		return attachment{}, err
	}
	h, size, err = v1.SHA256(bytes.NewReader(b))
	if err != nil {
		return attachment{}, err
	}
	if h != blob.Digest || size != blob.Size || size > policy.maxBytes {
		return attachment{}, fmt.Errorf("attestation envelope digest or size mismatch")
	}
	return attachment{envelope: b, digest: d.Digest.String()}, nil
}
