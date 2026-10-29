package sbomreuse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/kubescape/kubevuln/core/domain"
)

// CachedEligible rechecks the current policy on every imported cache hit. Storage
// is trusted cluster state, as with local SBOMs; the digest detects accidental
// payload/provenance mismatches, not an attacker authorized to rewrite both.
func (p *Provider) CachedEligible(b domain.SBOM, imageID string, opts domain.RegistryOptions) bool {
	if p == nil || p.policy == nil || b.Content == nil || b.Annotations[domain.SBOMImportSource] != "oci-attestation-v1" || b.Annotations[domain.SBOMImportPolicy] != p.policy.fingerprint {
		return false
	}
	ref, err := name.NewDigest(imageID, name.StrictValidation)
	if err != nil || ref.Name() != b.Annotations[domain.SBOMImportRequest] {
		return false
	}
	producer, ok := p.policy.repositories[ref.Context().Name()]
	if !ok {
		return false
	}
	if _, ok := producer.keys[b.Annotations[domain.SBOMImportSigner]]; !ok {
		return false
	}
	if b.SBOMCreatorName != "syft" || b.SBOMCreatorVersion != producer.SyftVersion || b.Annotations[domain.SBOMImportSchema] != producer.SchemaVersion {
		return false
	}
	if _, err := time.Parse(time.RFC3339, b.Annotations[domain.SBOMImportVerifiedAt]); err != nil {
		return false
	}
	if _, err := v1.NewHash(b.Annotations[domain.SBOMImportArtifact]); err != nil {
		return false
	}
	child, err := name.NewDigest(b.Annotations[domain.SBOMImportSubject], name.StrictValidation)
	if err != nil || child.Context().Name() != ref.Context().Name() {
		return false
	}
	platform, err := v1.ParsePlatform(b.Annotations[domain.ResolvedPlatformAnnotationKey])
	if err != nil {
		return false
	}
	if opts.Platform != "" {
		want, err := v1.ParsePlatform(opts.Platform)
		if err != nil || !samePlatform(*platform, *want) {
			return false
		}
	}
	raw, err := json.Marshal(b.Content)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != b.Annotations[domain.SBOMImportContent] {
		return false
	}
	var metadata struct {
		Source struct {
			Metadata struct {
				ImageID string `json:"imageID"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return false
	}
	h, err := v1.NewHash(child.DigestStr())
	if err != nil {
		return false
	}
	_, err = compatible(raw, subject{ref: child, descriptor: v1.Descriptor{Digest: h}, platform: *platform, configDigest: metadata.Source.Metadata.ImageID}, producer)
	return err == nil
}
