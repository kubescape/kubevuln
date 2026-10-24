package sbomreuse

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/require"
)

func TestAcquireVerifiedInventory(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "")
	require.NoError(t, err)
	p, key := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	publishEnvelope(t, repo, s, signStatement(t, s, inventory(t, s), key))
	provider := NewProvider(policy)
	sbom, err := provider.Acquire(context.Background(), "test-image", ref.Name(), domain.RegistryOptions{InsecureUseHTTP: true})
	require.NoError(t, err)
	require.True(t, sbom.Imported())
	require.Equal(t, "1.32.0", sbom.SBOMCreatorVersion)
	require.Equal(t, ref.Name(), sbom.Annotations[domain.SBOMImportSubject])
	_, err = provider.Acquire(context.Background(), "test-image", repo.Tag("latest").Name(), domain.RegistryOptions{})
	require.ErrorContains(t, err, "immutable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = provider.Acquire(ctx, "test-image", ref.Name(), domain.RegistryOptions{InsecureUseHTTP: true})
	require.ErrorIs(t, err, context.Canceled)
}
