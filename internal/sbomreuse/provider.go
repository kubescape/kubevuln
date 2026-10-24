package sbomreuse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/name"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/kubescape/kubevuln/internal/registryauth"
	"github.com/kubescape/kubevuln/internal/tools"
)

type Provider struct{ policy *CompiledPolicy }

func NewProvider(policy *CompiledPolicy) *Provider { return &Provider{policy: policy} }

// Acquire only accepts immutable references. Mutable tags, unsupported profiles and
// every acquisition failure are returned to the caller for normal generation.
func (p *Provider) Acquire(ctx context.Context, slug, imageID string, opts domain.RegistryOptions) (domain.SBOM, error) {
	result := "disabled"
	var fetched int64
	defer func() { metrics.RecordSBOMImport(ctx, result, fetched) }()
	if p == nil || p.policy == nil {
		return domain.SBOM{}, fmt.Errorf("SBOM reuse disabled")
	}
	nameOpts := []name.Option{name.StrictValidation}
	if opts.InsecureUseHTTP {
		nameOpts = append(nameOpts, name.Insecure)
	}
	result = "reference"
	ref, err := name.NewDigest(imageID, nameOpts...)
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("SBOM reuse requires an immutable repository digest")
	}
	result = "policy"
	producer, ok := p.policy.repositories[ref.Context().Name()]
	if !ok {
		return domain.SBOM{}, fmt.Errorf("repository not approved for SBOM reuse")
	}
	ctx, cancel := context.WithTimeout(ctx, p.policy.timeout)
	defer cancel()
	registryOpts := image.RegistryOptions{Credentials: registryauth.Credentials(opts.Credentials), InsecureUseHTTP: opts.InsecureUseHTTP, InsecureSkipTLSVerify: opts.InsecureSkipTLSVerify}
	get := func(ctx context.Context, _ string, ro *image.RegistryOptions) (domain.SBOM, error) {
		result = "resolution"
		c, err := newRegistryClient(ctx, ref.Context(), *ro, p.policy)
		if err != nil {
			return domain.SBOM{}, err
		}
		defer c.budget.base.(*http.Transport).CloseIdleConnections()
		defer func() { fetched += c.budget.fetchedBytes() }()
		s, err := c.resolve(ref, opts.Platform)
		if err != nil {
			return domain.SBOM{}, err
		}
		result = "discovery"
		a, err := c.discover(s, p.policy)
		if err != nil {
			return domain.SBOM{}, err
		}
		result = "verification"
		raw, signer, err := verify(ctx, a.envelope, s, producer)
		if err != nil {
			return domain.SBOM{}, err
		}
		result = "compatibility"
		doc, err := compatible(raw, s, producer)
		if err != nil {
			return domain.SBOM{}, err
		}
		stored, err := json.Marshal(doc)
		if err != nil {
			return domain.SBOM{}, err
		}
		hash := sha256.Sum256(stored)
		result = "accepted"
		return domain.SBOM{
			Name:               slug,
			Content:            doc,
			SBOMCreatorName:    "syft",
			SBOMCreatorVersion: producer.SyftVersion,
			Status:             helpersv1.Completed,
			Labels:             tools.LabelsFromImageID(s.ref.Name()),
			Annotations: map[string]string{
				domain.SBOMImportSource:              "oci-attestation-v1",
				domain.SBOMImportPolicy:              p.policy.fingerprint,
				domain.SBOMImportSigner:              signer,
				domain.SBOMImportArtifact:            a.digest,
				domain.SBOMImportSubject:             s.ref.Name(),
				domain.SBOMImportRequest:             ref.Name(),
				domain.SBOMImportContent:             hex.EncodeToString(hash[:]),
				domain.SBOMImportSchema:              producer.SchemaVersion,
				domain.SBOMImportVerifiedAt:          time.Now().UTC().Format(time.RFC3339),
				domain.ResolvedPlatformAnnotationKey: s.platform.String(),
				helpersv1.ImageIDMetadataKey:         s.ref.Name(),
				helpersv1.ToolVersionMetadataKey:     producer.SyftVersion,
			},
		}, nil
	}
	// Reuse the existing cloud-credential and anonymous fallback ladder. The empty
	// tag prevents MANIFEST_UNKNOWN from ever changing the immutable signed subject.
	return registryauth.ResolveSource(ctx, "sbom_import", get, ref.Name(), "", registryOpts)
}
