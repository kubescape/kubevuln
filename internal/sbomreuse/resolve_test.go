package sbomreuse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

func testRegistry(t *testing.T) (name.Repository, *registryClient) {
	t.Helper()
	s := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(s.Close)
	repo, err := name.NewRepository(strings.TrimPrefix(s.URL, "http://")+"/image", name.Insecure)
	require.NoError(t, err)
	p, _ := testPolicy(t, repo.Name())
	policy, err := CompilePolicy(p)
	require.NoError(t, err)
	optsForSetup := image.RegistryOptions{InsecureUseHTTP: true}
	budget, err := newRegistryTransport(repo, optsForSetup, policy)
	require.NoError(t, err)
	c := newRegistryClient(context.Background(), repo, optsForSetup, budget)
	t.Cleanup(func() { c.budget.base.(*http.Transport).CloseIdleConnections() })
	return repo, c
}

func publishImage(t *testing.T, repo name.Repository, arch string) name.Digest {
	t.Helper()
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: arch})
	require.NoError(t, err)
	h, err := img.Digest()
	require.NoError(t, err)
	ref := repo.Digest(h.String())
	require.NoError(t, remote.Write(ref, img))
	return ref
}

func TestResolvePlatformWithoutLayers(t *testing.T) {
	repo, c := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	s, err := c.resolve(ref, "linux/amd64")
	require.NoError(t, err)
	require.Equal(t, ref, s.ref)
	require.Equal(t, "amd64", s.platform.Architecture)
	_, err = c.resolve(ref, "amd64")
	require.NoError(t, err)
	_, err = c.resolve(ref, "linux/arm64")
	require.ErrorContains(t, err, "platform")
}

func TestResolveIndexRequiresUniqueExplicitPlatform(t *testing.T) {
	repo, c := testRegistry(t)
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}})
	h, err := idx.Digest()
	require.NoError(t, err)
	ref := repo.Digest(h.String())
	require.NoError(t, remote.WriteIndex(ref, idx))
	_, err = c.resolve(ref, "")
	require.ErrorContains(t, err, "explicit platform")
	s, err := c.resolve(ref, "linux/amd64")
	require.NoError(t, err)
	require.NotEqual(t, ref, s.ref)
}

func TestResolveWindowsVersion(t *testing.T) {
	repo, c := testRegistry(t)
	cfg := &v1.ConfigFile{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.0"}
	img, err := mutate.ConfigFile(empty.Image, cfg)
	require.NoError(t, err)
	platform := cfg.Platform()
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: platform}})
	h, err := idx.Digest()
	require.NoError(t, err)
	ref := repo.Digest(h.String())
	require.NoError(t, remote.WriteIndex(ref, idx))
	resolved, err := c.resolve(ref, platform.String())
	require.NoError(t, err)
	require.Equal(t, cfg.OSVersion, resolved.platform.OSVersion)
	_, err = c.resolve(ref, "windows/amd64")
	require.NoError(t, err)
	_, err = c.resolve(ref, "windows/amd64:10.0.17763.0")
	require.ErrorContains(t, err, "missing or ambiguous")
	_, err = c.resolve(resolved.ref, "windows/amd64:10.0.17763.0")
	require.ErrorContains(t, err, "configuration does not match")
}

func TestRegistryAttemptsShareRequestBudget(t *testing.T) {
	repo, setup := testRegistry(t)
	ref := publishImage(t, repo, "amd64")
	budget := setup.budget
	first := newRegistryClient(context.Background(), repo, image.RegistryOptions{}, budget)
	_, err := first.resolve(ref, "")
	require.NoError(t, err)
	firstRequests := budget.requests
	require.Positive(t, firstRequests)
	// Leave fewer requests than a complete second resolution needs.
	budget.requests = 65 - firstRequests
	retry := newRegistryClient(context.Background(), repo, image.RegistryOptions{}, budget)
	_, err = retry.resolve(ref, "")
	require.ErrorContains(t, err, "request budget exhausted")
}
