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
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/registryauth"
	"github.com/kubescape/kubevuln/internal/tools"
)

type Provider struct{ policy *CompiledPolicy }

func NewProvider(policy *CompiledPolicy) *Provider { return &Provider{policy: policy} }

// Acquire only accepts immutable references. Mutable tags, unsupported profiles and
// every acquisition failure are returned to the caller for normal generation.
func (p *Provider) Acquire(ctx context.Context, slug, imageID string, opts domain.RegistryOptions) (domain.SBOM, error) {
	if p == nil || p.policy == nil {
		return domain.SBOM{}, fmt.Errorf("SBOM reuse disabled")
	}
	nameOpts := []name.Option{name.StrictValidation}
	if opts.InsecureUseHTTP {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.NewDigest(imageID, nameOpts...)
	if err != nil {
		return domain.SBOM{}, fmt.Errorf("SBOM reuse requires an immutable repository digest")
	}
	producer, ok := p.policy.repositories[ref.Context().Name()]
	if !ok {
		return domain.SBOM{}, fmt.Errorf("repository not approved for SBOM reuse")
	}
	ctx, cancel := context.WithTimeout(ctx, p.policy.timeout)
	defer cancel()
	registryOpts := image.RegistryOptions{Credentials: registryauth.Credentials(opts.Credentials), InsecureUseHTTP: opts.InsecureUseHTTP, InsecureSkipTLSVerify: opts.InsecureSkipTLSVerify}
	firstAttempt := true
	get := func(ctx context.Context, _ string, ro *image.RegistryOptions) (domain.SBOM, error) {
		attempt := *ro
		// Consult Docker credentials only on the initial attempt. ResolveSource's
		// final retry clears explicit credentials and must stay truly anonymous.
		if firstAttempt {
			attempt.Keychain = authn.DefaultKeychain
		}
		firstAttempt = false
		c, err := newRegistryClient(ctx, ref.Context(), attempt, p.policy)
		if err != nil {
			return domain.SBOM{}, err
		}
		defer c.budget.base.(*http.Transport).CloseIdleConnections()
		s, err := c.resolve(ref, opts.Platform)
		if err != nil {
			return domain.SBOM{}, err
		}
		a, err := c.discover(s, p.policy)
		if err != nil {
			return domain.SBOM{}, err
		}
		raw, signer, err := verify(ctx, a.envelope, s, producer)
		if err != nil {
			return domain.SBOM{}, err
		}
		doc, err := compatible(raw, s, producer)
		if err != nil {
			return domain.SBOM{}, err
		}
		stored, err := json.Marshal(doc)
		if err != nil {
			return domain.SBOM{}, err
		}
		hash := sha256.Sum256(stored)
		return domain.SBOM{Name: slug, Content: doc, SBOMCreatorName: "syft", SBOMCreatorVersion: producer.SyftVersion, Status: helpersv1.Completed, Labels: tools.LabelsFromImageID(s.ref.Name()), Annotations: map[string]string{
			domain.SBOMImportSource: "oci-attestation-v1", domain.SBOMImportPolicy: p.policy.fingerprint, domain.SBOMImportSigner: signer, domain.SBOMImportArtifact: a.digest, domain.SBOMImportSubject: s.ref.Name(), domain.SBOMImportRequest: ref.Name(), domain.SBOMImportContent: hex.EncodeToString(hash[:]), domain.SBOMImportSchema: producer.SchemaVersion, domain.SBOMImportVerifiedAt: time.Now().UTC().Format(time.RFC3339), domain.ResolvedPlatformAnnotationKey: s.platform.String(), helpersv1.ImageIDMetadataKey: s.ref.Name(), helpersv1.ToolVersionMetadataKey: producer.SyftVersion,
		}}, nil
	}
	// Reuse the existing cloud-credential and anonymous fallback ladder. The empty
	// tag prevents MANIFEST_UNKNOWN from ever changing the immutable signed subject.
	return registryauth.ResolveSource(ctx, "sbom_import", get, ref.Name(), "", registryOpts)
}
