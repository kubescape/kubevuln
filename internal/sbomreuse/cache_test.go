package sbomreuse

import (
	"context"
	"testing"

	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/require"
)

func TestCachePolicyRotationAndPayloadIntegrity(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "")
	require.NoError(t, err)
	p, key := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	provider := NewProvider(policy)
	publishEnvelope(t, repo, s, signStatement(t, s, inventory(t, s), key))
	opts := domain.RegistryOptions{InsecureUseHTTP: true}
	b, err := provider.Acquire(context.Background(), "image", ref.Name(), opts)
	require.NoError(t, err)
	require.True(t, provider.CachedEligible(b, ref.Name(), opts))
	rotated, _ := testPolicy(t, repo.Name())
	other, err := CompilePolicy(rotated)
	require.NoError(t, err)
	require.False(t, NewProvider(other).CachedEligible(b, ref.Name(), opts))
	require.False(t, provider.CachedEligible(b, ref.Name(), domain.RegistryOptions{Platform: "linux/arm64"}))
	b.Content.Artifacts = nil
	require.False(t, provider.CachedEligible(b, ref.Name(), opts))
}
