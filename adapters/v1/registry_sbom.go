package v1

import (
	"context"
	"encoding/json"
	"fmt"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
)

type InventoryAcquirer interface {
	Acquire(context.Context, string, string, domain.RegistryOptions) (domain.SBOM, error)
}

func (a *RegistrySBOMAdapter) ValidateCachedSBOM(ctx context.Context, b domain.SBOM) bool {
	w, ok := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	if !ok || w.Wlid != "" || w.InstanceID != "" {
		return false
	}
	validator, ok := a.provider.(interface {
		CachedEligible(domain.SBOM, string, domain.RegistryOptions) bool
	})
	if !ok {
		return false
	}
	ref := w.ImageHash
	if w.ImageTagNormalized != "" {
		ref = NormalizeImageID(ref, w.ImageTagNormalized)
	}
	platform, _ := w.Args[domain.ArgsPlatform].(string)
	bts, err := json.Marshal(b.Content)
	return err == nil && len(bts) <= a.GetMaxSBOMSize() && validator.CachedEligible(b, ref, domain.RegistryOptions{Platform: platform})
}

// RegistrySBOMAdapter tries a verified inventory before the selected in-process or
// sidecar creator. Embedding preserves the fallback's version and resource limits.
type RegistrySBOMAdapter struct {
	ports.SBOMCreator
	provider InventoryAcquirer
}

func NewRegistrySBOMAdapter(fallback ports.SBOMCreator, provider InventoryAcquirer) *RegistrySBOMAdapter {
	return &RegistrySBOMAdapter{SBOMCreator: fallback, provider: provider}
}

func (a *RegistrySBOMAdapter) CreateSBOM(ctx context.Context, slug, imageID, imageTag string, opts domain.RegistryOptions) (domain.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	w, _ := ctx.Value(domain.WorkloadKey{}).(domain.ScanCommand)
	// Runtime relevancy needs an independently agreed file-inventory contract.
	// Its initial profile deliberately stays on the existing generation path.
	if a.provider != nil && w.Wlid == "" && w.InstanceID == "" {
		ref := imageID
		if imageTag != "" {
			ref = NormalizeImageID(imageID, imageTag)
		}
		sbom, err := a.provider.Acquire(ctx, slug, ref, opts)
		if err == nil && sbom.Content != nil && sbom.Imported() && sbom.Status == helpersv1.Completed {
			b, marshalErr := json.Marshal(sbom.Content)
			if marshalErr == nil && len(b) <= a.GetMaxSBOMSize() {
				sbom.Annotations[helpersv1.ImageTagMetadataKey] = imageTag
				return sbom, nil
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return domain.SBOM{}, err
	}
	sbom, err := a.SBOMCreator.CreateSBOM(ctx, slug, imageID, imageTag, opts)
	// A fallback that returns no inventory and no terminal status must not become
	// an apparently successful empty scan.
	if err == nil && sbom.Content == nil && sbom.Status != helpersv1.TooLarge && sbom.Status != helpersv1.Incomplete && sbom.Status != helpersv1.Unauthorize {
		return domain.SBOM{}, fmt.Errorf("SBOM generation returned no inventory")
	}
	return sbom, err
}
