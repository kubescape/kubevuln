package repositories

import (
	"context"
	"testing"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

func TestImportedSBOMStoragePreservesProducerAndRequiresPolicyCheck(t *testing.T) {
	s := NewFakeAPIServerStorage("kubescape")
	ctx := context.Background()
	b := domain.SBOM{Name: "image", SBOMCreatorName: "syft", SBOMCreatorVersion: "1.32.0", Content: &v1beta1.SyftDocument{}, Status: helpersv1.Completed, Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1", domain.SBOMImportPolicy: "old", "user.annotation": "keep"}}
	require.NoError(t, s.StoreSBOM(ctx, b, false))
	got, err := s.GetSBOM(ctx, "image", "1.32.0")
	require.ErrorIs(t, err, domain.ErrOutdatedSBOM)
	require.True(t, got.Imported())
	require.Equal(t, "syft", got.SBOMCreatorName)
	require.Equal(t, "1.32.0", got.SBOMCreatorVersion)
	b.Annotations = map[string]string{}
	b.SBOMCreatorVersion = "1.42.0"
	require.NoError(t, s.StoreSBOM(ctx, b, false))
	got, err = s.GetSBOM(ctx, "image", "1.42.0")
	require.NoError(t, err)
	require.False(t, got.Imported())
	require.Equal(t, "keep", got.Annotations["user.annotation"])
}

func TestImportedCVEDoesNotBypassTrustRevalidation(t *testing.T) {
	s := NewFakeAPIServerStorage("kubescape")
	ctx := context.Background()
	c := domain.CVEManifest{Name: "image", Content: &v1beta1.GrypeDocument{}, Annotations: map[string]string{domain.SBOMImportSource: "oci-attestation-v1"}}
	require.NoError(t, s.StoreCVE(ctx, c, false))
	got, err := s.GetCVE(ctx, "image", "", "", "")
	require.NoError(t, err)
	require.Nil(t, got.Content)
	c.Annotations = map[string]string{}
	require.NoError(t, s.StoreCVE(ctx, c, false))
	got, err = s.GetCVE(ctx, "image", "", "", "")
	require.NoError(t, err)
	require.NotNil(t, got.Content)
	require.Empty(t, got.Annotations[domain.SBOMImportSource])
}
