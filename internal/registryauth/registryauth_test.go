package registryauth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

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
	defer func() { ECRCredsFn = orig }()

	var gotRegion string
	ECRCredsFn = func(_ context.Context, region string) (*image.RegistryCredentials, error) {
		gotRegion = region
		return &image.RegistryCredentials{Username: "AWS", Password: "secret"}, nil
	}

	creds, err := ECR{}.Credentials(context.Background(), "123456789012.dkr.ecr.ap-south-1.amazonaws.com/app:v1")

	require.NoError(t, err)
	assert.Equal(t, "ap-south-1", gotRegion)
	assert.Equal(t, "AWS", creds.Username)
	assert.Equal(t, "secret", creds.Password)
}

func TestCredentialsFromAuthorizationToken(t *testing.T) {
	tokenFor := func(s string) *ecr.GetAuthorizationTokenOutput {
		encoded := base64.StdEncoding.EncodeToString([]byte(s))
		return &ecr.GetAuthorizationTokenOutput{
			AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &encoded}},
		}
	}

	t.Run("decodes user and password", func(t *testing.T) {
		creds, err := credentialsFromAuthorizationToken(tokenFor("AWS:pa55word"))
		require.NoError(t, err)
		assert.Equal(t, "AWS", creds.Username)
		assert.Equal(t, "pa55word", creds.Password)
	})

	// ECR passwords are opaque blobs that routinely contain colons, so only the first one
	// separates the user from the password.
	t.Run("password may contain colons", func(t *testing.T) {
		creds, err := credentialsFromAuthorizationToken(tokenFor("AWS:aa:bb:cc"))
		require.NoError(t, err)
		assert.Equal(t, "AWS", creds.Username)
		assert.Equal(t, "aa:bb:cc", creds.Password)
	})

	t.Run("nil output", func(t *testing.T) {
		_, err := credentialsFromAuthorizationToken(nil)
		assert.ErrorIs(t, err, errNoAuthorizationData)
	})

	t.Run("no authorization data", func(t *testing.T) {
		_, err := credentialsFromAuthorizationToken(&ecr.GetAuthorizationTokenOutput{})
		assert.ErrorIs(t, err, errNoAuthorizationData)
	})

	t.Run("token without a colon", func(t *testing.T) {
		_, err := credentialsFromAuthorizationToken(tokenFor("no-separator"))
		assert.ErrorIs(t, err, errMalformedAuthorizationToken)
	})

	t.Run("token is not base64", func(t *testing.T) {
		bad := "!!!not-base64!!!"
		_, err := credentialsFromAuthorizationToken(&ecr.GetAuthorizationTokenOutput{
			AuthorizationData: []ecrtypes.AuthorizationData{{AuthorizationToken: &bad}},
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, errNoAuthorizationData)
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
	defer func() { GCPCredsFn = orig }()

	want := errors.New("ADC unavailable")
	GCPCredsFn = func(context.Context) (*image.RegistryCredentials, error) { return nil, want }

	_, err := GCP{}.Credentials(context.Background(), "gcr.io/foo/bar")
	assert.ErrorIs(t, err, want)
}
