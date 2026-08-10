package services

import (
	"context"
	"testing"
	"time"

	"github.com/docker/docker/api/types/registry"
	"github.com/kubescape/kubevuln/adapters"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanService_RateLimitIsCredentialBlind(t *testing.T) {
	// 1. Setup two identical image definitions, one unauthenticated and one authenticated
	imageTag := "docker.io/library/nginx:latest"

	unauthenticatedWorkload := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		ImageSlug:          "nginx-slug",
		// No credentials
	}

	authenticatedWorkload := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		ImageSlug:          "nginx-slug",
		CredentialsList: []registry.AuthConfig{
			{
				Username:      "tenant-a-user",
				Password:      "super-secret-token",
				ServerAddress: "https://index.docker.io/v1/",
			},
		},
	}

	// 2. We assert that their cache keys SHOULD be different so they don't block each other.
	// We assert that their cache keys SHOULD be different so they don't block each other.
	require.NotEqual(t, rateLimitCacheKey(unauthenticatedWorkload), rateLimitCacheKey(authenticatedWorkload),
		"Expected cache keys to differ when credentials are provided, preventing cross-tenant DoS")

	// 3. To demonstrate the DoS effect on ScanRegistry:
	platform := &recordingPlatform{}
	countingSBOM := &countingSBOMCreator{SBOMCreator: adapters.NewMockSBOMAdapter(false, false, false)}
	cveAdapter := adapters.NewMockCVEAdapter()
	s := NewScanService(countingSBOM, repositories.NewMemoryStorage(false, false), cveAdapter, repositories.NewMemoryStorage(false, false), platform, nil, false, false, true, false, false)

	// Simulate unauthenticated workload hitting 429
	s.tooManyRequests.Set(rateLimitCacheKey(unauthenticatedWorkload), true, 10*time.Minute)

	// Now try to scan with the AUTHENTICATED workload.
	// It should NOT be blocked, but because of the bug, it will be.
	authCtx := enrichContext(context.TODO(), authenticatedWorkload, s.Version())

	scanErr := s.ScanRegistry(authCtx)
	assert.NoError(t, scanErr, "Authenticated workload should not be blocked by unauthenticated workload's 429")
}

func TestScanService_RateLimitCacheKey_BoundaryCollision(t *testing.T) {
	// A poorly encoded credential hash (like direct concatenation) would yield
	// the same key for (Username="a", ServerAddress="bc") and (Username="ab", ServerAddress="c").
	// This test ensures boundaries are respected.
	imageTag := "docker.io/library/nginx:latest"

	workload1 := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		CredentialsList: []registry.AuthConfig{
			{Username: "a", ServerAddress: "bc"},
		},
	}

	workload2 := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		CredentialsList: []registry.AuthConfig{
			{Username: "ab", ServerAddress: "c"},
		},
	}

	require.NotEqual(t, rateLimitCacheKey(workload1), rateLimitCacheKey(workload2),
		"Cache keys must differ for split-field collisions")
}

func TestScanService_RateLimitCacheKey_SameUsernameDifferentPassword(t *testing.T) {
	imageTag := "docker.io/library/nginx:latest"

	workload1 := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		CredentialsList: []registry.AuthConfig{
			{Username: "shared-user", Password: "password-A"},
		},
	}

	workload2 := domain.ScanCommand{
		ImageTagNormalized: imageTag,
		CredentialsList: []registry.AuthConfig{
			{Username: "shared-user", Password: "password-B"},
		},
	}

	require.NotEqual(t, rateLimitCacheKey(workload1), rateLimitCacheKey(workload2),
		"Cache keys must differ for workloads with same Username but different Passwords")
}
