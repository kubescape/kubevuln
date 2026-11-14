package sbomreuse

import (
	"context"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
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
	require.True(t, provider.CachedEligible(b, ref.Name(), domain.RegistryOptions{Platform: "amd64"}))
	rotated, _ := testPolicy(t, repo.Name())
	other, err := CompilePolicy(rotated)
	require.NoError(t, err)
	require.False(t, NewProvider(other).CachedEligible(b, ref.Name(), opts))
	require.False(t, provider.CachedEligible(b, ref.Name(), domain.RegistryOptions{Platform: "linux/arm64"}))
	b.Content.Artifacts = nil
	require.False(t, provider.CachedEligible(b, ref.Name(), opts))
}

func TestCacheWindowsVersionAndStatusOnlyWrite(t *testing.T) {
	ctx := context.Background()
	repo, c := testRegistry(t)
	cfg := &v1.ConfigFile{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.0"}
	img, err := mutate.ConfigFile(empty.Image, cfg)
	require.NoError(t, err)
	h, err := img.Digest()
	require.NoError(t, err)
	ref := repo.Digest(h.String())
	require.NoError(t, remote.Write(ref, img))
	opts := domain.RegistryOptions{InsecureUseHTTP: true, Platform: cfg.Platform().String()}
	s, err := c.resolve(ref, opts.Platform)
	require.NoError(t, err)
	p, key := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	provider := NewProvider(policy)
	publishEnvelope(t, repo, s, signStatement(t, s, inventory(t, s), key))
	b, err := provider.Acquire(ctx, "image", ref.Name(), opts)
	require.NoError(t, err)
	require.Equal(t, opts.Platform, b.Annotations[domain.ResolvedPlatformAnnotationKey])
	require.True(t, provider.CachedEligible(b, ref.Name(), opts))
	require.False(t, provider.CachedEligible(b, ref.Name(), domain.RegistryOptions{Platform: "windows/amd64:10.0.17763.0"}))

	store := repositories.NewFakeAPIServerStorage("kubescape")
	require.NoError(t, store.StoreSBOM(ctx, b, false))
	require.NoError(t, store.StoreSBOM(ctx, domain.SBOM{Name: b.Name, Status: helpersv1.TooLarge}, false))
	cached, err := store.GetSBOM(ctx, b.Name, b.SBOMCreatorVersion)
	require.ErrorIs(t, err, domain.ErrOutdatedSBOM)
	require.True(t, cached.Imported())
	require.Equal(t, helpersv1.TooLarge, cached.Status)
	require.False(t, provider.CachedEligible(cached, ref.Name(), opts))
}
