package registryauth

import (
	"context"
	"encoding/base64"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/kubescape/kubevuln/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsGCPRegistry(t *testing.T) {
	tests := []struct {
		imageID string
		want    bool
	}{
		{"gcr.io/foo/bar", true},
		{"us.gcr.io/foo/bar", true},
		{"us-docker.pkg.dev/foo/bar", true},
		{"europe-west1-docker.pkg.dev/project/repo/image:tag", true},
		{"quay.io/foo/bar", false},
		{"quay.io/foo/bar-docker.pkg.dev/x", false},
		{"index.docker.io/library/alpine", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			assert.Equal(t, tt.want, IsGCPRegistry(tt.imageID))
		})
	}
}

func TestECRMatchesAndRegion(t *testing.T) {
	tests := []struct {
		name       string
		imageID    string
		wantRegion string
	}{
		{name: "standard", imageID: "123456789012.dkr.ecr.us-east-1.amazonaws.com/team/app:v1", wantRegion: "us-east-1"},
		{name: "with digest", imageID: "123456789012.dkr.ecr.eu-west-2.amazonaws.com/app@sha256:abc", wantRegion: "eu-west-2"},
		{name: "fips", imageID: "123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com/app:v1", wantRegion: "us-gov-west-1"},
		{name: "china partition", imageID: "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app:v1", wantRegion: "cn-north-1"},
		// ECR Public serves anonymous pulls, so the anonymous fallback already covers it.
		{name: "ecr public is not matched", imageID: "public.ecr.aws/nginx/nginx:latest", wantRegion: ""},
		{name: "short account id", imageID: "12345.dkr.ecr.us-east-1.amazonaws.com/app:v1", wantRegion: ""},
		{name: "lookalike host", imageID: "evil.com/123456789012.dkr.ecr.us-east-1.amazonaws.com/app", wantRegion: ""},
		{name: "suffix lookalike", imageID: "notamazonaws.com/app", wantRegion: ""},
		{name: "gcp is not ecr", imageID: "gcr.io/foo/bar", wantRegion: ""},
		{name: "empty", imageID: "", wantRegion: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantRegion, ecrRegion(tt.imageID))
			assert.Equal(t, tt.wantRegion != "", ECR{}.Matches(tt.imageID))
		})
	}
}

// The region has to come from the image reference: a cluster in one region can pull from a
// registry in another, so ambient AWS config is not a safe source for it.
func TestECRCredentialsUsesRegionFromReference(t *testing.T) {
	orig := ECRCredsFn
	defer func() { ECRCredsFn = orig; ResetCaches() }()
	ResetCaches()

	var gotRegion string
	ECRCredsFn = func(_ context.Context, region string) (*image.RegistryCredentials, time.Time, error) {
		gotRegion = region
		return &image.RegistryCredentials{Username: "AWS", Password: "secret"}, time.Now().Add(time.Hour), nil
	}

	creds, err := ECR{}.Credentials(context.Background(), "123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:v1")

	require.NoError(t, err)
	assert.Equal(t, "ap-south-1", gotRegion)
	assert.Equal(t, "AWS", creds.Username)
	assert.Equal(t, "secret", creds.Password)
}

// Two AWS accounts pulling through the same region must not share a cache entry: the
// ambient credential chain resolves a token scoped to one specific account, so handing that
// token to a pull against a different account fails with a 401.
func TestECRCredentialsIsolatesCacheAcrossAccountsInSameRegion(t *testing.T) {
	orig := ECRCredsFn
	defer func() { ECRCredsFn = orig; ResetCaches() }()
	ResetCaches()

	calls := map[string]int{}
	ECRCredsFn = func(_ context.Context, region string) (*image.RegistryCredentials, time.Time, error) {
		calls[region]++
		return &image.RegistryCredentials{Username: "AWS", Password: region}, time.Now().Add(time.Hour), nil
	}

	accountA := "111111111111.dkr.ecr.us-east-1.amazonaws.com/app:v1"
	accountB := "222222222222.dkr.ecr.us-east-1.amazonaws.com/app:v1"

	credsA, err := ECR{}.Credentials(context.Background(), accountA)
	require.NoError(t, err)
	credsB, err := ECR{}.Credentials(context.Background(), accountB)
	require.NoError(t, err)

	assert.Equal(t, 2, calls["us-east-1"], "same-region pull from a different account must not be served from the first account's cache entry")

	// Fetch each account again: both should now be served from their own cache entry, not
	// refetched and not cross-served from the other account's entry.
	credsA2, err := ECR{}.Credentials(context.Background(), accountA)
	require.NoError(t, err)
	credsB2, err := ECR{}.Credentials(context.Background(), accountB)
	require.NoError(t, err)

	assert.Equal(t, 2, calls["us-east-1"], "repeat pulls for already-cached accounts must not refetch")
	assert.Same(t, credsA, credsA2)
	assert.Same(t, credsB, credsB2)
}

// GCP credentials are cached per registry host: nothing in Credentials guarantees the
// ambient identity resolves to the same token for every GCR/Artifact Registry host a pod
// might pull from (workload identity federation can map different callers to different
// service accounts), so one host's cached token must never be handed out for another host.
func TestGCPCredentialsIsolatesCacheAcrossHosts(t *testing.T) {
	orig := GCPCredsFn
	defer func() { GCPCredsFn = orig; ResetCaches() }()
	ResetCaches()

	var calls int32
	GCPCredsFn = func(context.Context) (*image.RegistryCredentials, time.Time, error) {
		n := atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Username: "oauth2accesstoken", Password: string(rune('a' + n))}, time.Now().Add(time.Hour), nil
	}

	hostA := "gcr.io/foo/bar:v1"
	hostB := "us-docker.pkg.dev/project/repo/image:v1"

	credsA, err := GCP{}.Credentials(context.Background(), hostA)
	require.NoError(t, err)
	credsB, err := GCP{}.Credentials(context.Background(), hostB)
	require.NoError(t, err)

	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "a different registry host must not be served from another host's cache entry")
	assert.NotEqual(t, credsA.Password, credsB.Password)

	credsA2, err := GCP{}.Credentials(context.Background(), hostA)
	require.NoError(t, err)
	assert.Same(t, credsA, credsA2, "repeat pulls for an already-cached host must not refetch")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
}

func TestCredentialsFromAuthorizationToken(t *testing.T) {
	tokenFor := func(s string) *ecr.GetAuthorizationTokenOutput {
		encoded := base64.StdEncoding.EncodeToString([]byte(s))
		return &ecr.GetAuthorizationTokenOutput{
			AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &encoded}},
		}
	}

	t.Run("decodes user and password", func(t *testing.T) {
		creds, _, err := credentialsFromAuthorizationToken(tokenFor("AWS:pa55word"))
		require.NoError(t, err)
		assert.Equal(t, "AWS", creds.Username)
		assert.Equal(t, "pa55word", creds.Password)
	})

	// ECR passwords are opaque blobs that routinely contain colons, so only the first one
	// separates the user from the password.
	t.Run("password may contain colons", func(t *testing.T) {
		creds, _, err := credentialsFromAuthorizationToken(tokenFor("AWS:aa:bb:cc"))
		require.NoError(t, err)
		assert.Equal(t, "AWS", creds.Username)
		assert.Equal(t, "aa:bb:cc", creds.Password)
	})

	t.Run("nil output", func(t *testing.T) {
		_, _, err := credentialsFromAuthorizationToken(nil)
		assert.ErrorIs(t, err, errNoAuthorizationData)
	})

	t.Run("no authorization data", func(t *testing.T) {
		_, _, err := credentialsFromAuthorizationToken(&ecr.GetAuthorizationTokenOutput{})
		assert.ErrorIs(t, err, errNoAuthorizationData)
	})

	t.Run("token without a colon", func(t *testing.T) {
		_, _, err := credentialsFromAuthorizationToken(tokenFor("no-separator"))
		assert.ErrorIs(t, err, errMalformedAuthorizationToken)
	})

	t.Run("token is not base64", func(t *testing.T) {
		bad := "!!!not-base64!!!"
		_, _, err := credentialsFromAuthorizationToken(&ecr.GetAuthorizationTokenOutput{
			AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &bad}},
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, errNoAuthorizationData)
	})

	// The cache relies on this expiry to know when to refetch (see cache.go), so it must
	// come from ECR's own response, not be assumed from the package doc's "12 hours".
	t.Run("reports ECR's own expiry", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("AWS:pa55word"))
		want := time.Now().Add(6 * time.Hour).Truncate(time.Second)
		_, expiry, err := credentialsFromAuthorizationToken(&ecr.GetAuthorizationTokenOutput{
			AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &encoded, ExpiresAt: &want}},
		})
		require.NoError(t, err)
		assert.True(t, want.Equal(expiry))
	})

	t.Run("no ExpiresAt yields a zero expiry, not an error", func(t *testing.T) {
		_, expiry, err := credentialsFromAuthorizationToken(tokenFor("AWS:pa55word"))
		require.NoError(t, err)
		assert.True(t, expiry.IsZero())
	})
}

func TestFor(t *testing.T) {
	tests := []struct {
		name         string
		imageID      string
		wantFound    bool
		wantStrategy string
	}{
		{name: "gcp", imageID: "gcr.io/foo/bar", wantFound: true, wantStrategy: metrics.FallbackStrategyGCPADC},
		{name: "ecr", imageID: "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:v1", wantFound: true, wantStrategy: metrics.FallbackStrategyECR},
		{name: "neither", imageID: "index.docker.io/library/alpine", wantFound: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, ok := For(tt.imageID)
			require.Equal(t, tt.wantFound, ok)
			if tt.wantFound {
				assert.Equal(t, tt.wantStrategy, provider.Strategy())
			}
		})
	}
}

// Each provider must report a distinct strategy, otherwise a fallback gets attributed to the
// wrong cloud in the metrics.
func TestProviderStrategiesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Providers {
		s := p.Strategy()
		assert.NotEmpty(t, s)
		assert.False(t, seen[s], "duplicate strategy %q", s)
		seen[s] = true
	}
}

func TestGCPCredentialsFailurePropagates(t *testing.T) {
	orig := GCPCredsFn
	defer func() { GCPCredsFn = orig; ResetCaches() }()
	ResetCaches()

	want := errors.New("ADC unavailable")
	GCPCredsFn = func(context.Context) (*image.RegistryCredentials, time.Time, error) { return nil, time.Time{}, want }

	_, err := GCP{}.Credentials(context.Background(), "gcr.io/foo/bar")
	assert.ErrorIs(t, err, want)
}
