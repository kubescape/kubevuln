package services

import (
	"context"
	"testing"

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
