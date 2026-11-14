package services

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/core/ports"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

type importCacheCreator struct {
	ports.SBOMCreator
	eligible bool
	checked  int
}

func (c *importCacheCreator) ValidateCachedSBOM(context.Context, domain.SBOM) bool {
	c.checked++
	return c.eligible
}

func TestScanServiceImportedCachePolicy(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		generation, eligible, want bool
	}{
		{"eligible", true, true, true}, {"revoked", true, false, false}, {"generation disabled", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := repositories.NewFakeAPIServerStorage("kubescape")
			ctx := context.Background()
			b := domain.SBOM{Name: "image", SBOMCreatorName: "syft", SBOMCreatorVersion: "1.32.0", Content: &v1beta1.SyftDocument{}, Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1"}}
			require.NoError(t, store.StoreSBOM(ctx, b, false))
			creator := &importCacheCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false), eligible: tc.eligible}
			s := &ScanService{sbomRepository: store, sbomCreator: creator, sbomGeneration: tc.generation}
			got, err := s.getSBOM(ctx, "image", "local-version")
			require.NoError(t, err)
			require.Equal(t, tc.want, got.Content != nil)
			if tc.generation {
				require.Equal(t, 1, creator.checked)
			} else {
				require.Zero(t, creator.checked)
			}
		})
	}
}

func TestWorkloadReusesTooLargeVerdictAfterImport(t *testing.T) {
	store := repositories.NewFakeAPIServerStorage("kubescape")
	fallback := &sizeCappedSBOMCreator{status: helpersv1.TooLarge}
	creator := &importCacheCreator{SBOMCreator: fallback}
	s := NewScanService(creator, store, adapters.NewMockCVEAdapter(), store, adapters.NewMockPlatform(false, nil), adapters.NewMockRelevancyAdapter(), true, false, true, false, false)
	workload := domain.ScanCommand{ImageSlug: "image", ImageHash: "test/app@sha256:c1b135231b5b1a6799346cd701da4b59e5b7ef8e694ec7b04fb23b8dbe144137", Wlid: "wlid://cluster-test/namespace-default/deployment-demo"}
	ctx, err := s.ValidateGenerateSBOM(context.Background(), workload)
	require.NoError(t, err)
	require.NoError(t, store.StoreSBOM(ctx, domain.SBOM{Name: workload.ImageSlug, Status: helpersv1.Completed, Content: &v1beta1.SyftDocument{}, Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1"}}, false))

	require.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM)
	require.ErrorIs(t, s.GenerateSBOM(ctx), domain.ErrIncompleteSBOM)
	require.Equal(t, 1, fallback.calls)
	got, err := s.getSBOM(ctx, workload.ImageSlug, creator.Version())
	require.NoError(t, err)
	require.Equal(t, helpersv1.TooLarge, got.Status)
	require.Nil(t, got.Content)

	// Registry-only scans must still get a chance to acquire a verified inventory.
	registryCtx := context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{ImageSlug: workload.ImageSlug})
	got, err = s.getSBOM(registryCtx, workload.ImageSlug, creator.Version())
	require.NoError(t, err)
	require.Empty(t, got.Status)
	require.Nil(t, got.Content)
}
