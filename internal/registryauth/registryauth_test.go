package registryauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
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
		{"GCR.IO/foo/bar", true},
		{"us.gcr.io/foo/bar", true},
		{"US.GCR.IO/foo/bar", true},
		{"us-docker.pkg.dev/foo/bar", true},
		{"US-DOCKER.PKG.DEV/foo/bar", true},
		{"europe-west1-docker.pkg.dev/project/repo/image:tag", true},
		{"EUROPE-WEST1-DOCKER.PKG.DEV/project/repo/image:tag", true},
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

func TestIsACRRegistry(t *testing.T) {
	tests := []struct {
		imageID string
		want    bool
	}{
		{"myregistry.azurecr.io/foo/bar", true},
		{"MYREGISTRY.AZURECR.IO/foo/bar", true},
		{"azurecr.io/foo/bar", false},
		{"myregistry.azurecr.cn/foo/bar", true},
		{"myregistry.azurecr.us/foo/bar", true},
		{"myregistry.azurecr.de/foo/bar", true},
		{"quay.io/myregistry.azurecr.io/bar", false},
		{"evilazurecr.io/foo/bar", false},
		{"index.docker.io/library/alpine", false},
		{"gcr.io/foo/bar", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.imageID, func(t *testing.T) {
			assert.Equal(t, tt.want, IsACRRegistry(tt.imageID))
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
		{name: "standard uppercase", imageID: "123456789012.DKR.ECR.US-EAST-1.AMAZONAWS.COM/team/app:v1", wantRegion: "us-east-1"},
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
		{name: "acr", imageID: "myregistry.azurecr.io/app:v1", wantFound: true, wantStrategy: metrics.FallbackStrategyACR},
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

func TestACRCloudConfig(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		wantScope     string
		wantAuthority string
	}{
		{
			name:          "public commercial cloud",
			host:          "myregistry.azurecr.io",
			wantScope:     "https://containerregistry.azure.net/.default",
			wantAuthority: cloud.AzurePublic.ActiveDirectoryAuthorityHost,
		},
		{
			name:          "china cloud",
			host:          "myregistry.azurecr.cn",
			wantScope:     "https://containerregistry.azure.cn/.default",
			wantAuthority: cloud.AzureChina.ActiveDirectoryAuthorityHost,
		},
		{
			name:          "us government cloud",
			host:          "myregistry.azurecr.us",
			wantScope:     "https://containerregistry.azure.us/.default",
			wantAuthority: cloud.AzureGovernment.ActiveDirectoryAuthorityHost,
		},
		{
			name:          "germany legacy cloud",
			host:          "myregistry.azurecr.de",
			wantScope:     "https://containerregistry.azure.de/.default",
			wantAuthority: "https://login.microsoftonline.de/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, scope, _ := acrCloudConfig(tt.host)
			assert.Equal(t, tt.wantScope, scope)
			assert.Equal(t, tt.wantAuthority, opts.Cloud.ActiveDirectoryAuthorityHost)
		})
	}
}

func testJWTWithExpiry(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"none"}`))
	claims, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(claims)
	return fmt.Sprintf("%s.%s.signature", header, payload)
}

func TestACRExchange_Successful(t *testing.T) {
	expectedEntraToken := "entra-access-token-123"
	expectedRefreshToken := testJWTWithExpiry(time.Now().Add(2 * time.Hour))

	var receivedMethod, receivedContentType, receivedGrantType, receivedService, receivedAccessToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/exchange" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		receivedMethod = r.Method
		receivedContentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		receivedGrantType = r.PostForm.Get("grant_type")
		receivedService = r.PostForm.Get("service")
		receivedAccessToken = r.PostForm.Get("access_token")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": expectedRefreshToken})
	}))
	defer server.Close()

	serverHost := strings.TrimPrefix(server.URL, "http://")

	origHTTP := acrHTTPClient
	origTokenFn := ACRTokenFn
	defer func() {
		acrHTTPClient = origHTTP
		ACRTokenFn = origTokenFn
		ResetCaches()
	}()
	ResetCaches()

	acrHTTPClient = server.Client()
	ACRTokenFn = func(_ context.Context, _ string) (string, time.Time, error) {
		return expectedEntraToken, time.Now().Add(time.Hour), nil
	}

	creds, expiry, err := acrCredentials(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, receivedMethod)
	assert.Equal(t, "application/x-www-form-urlencoded", receivedContentType)
	assert.Equal(t, "access_token", receivedGrantType)
	assert.Equal(t, serverHost, receivedService)
	assert.Equal(t, expectedEntraToken, receivedAccessToken)

	assert.Equal(t, "00000000-0000-0000-0000-000000000000", creds.Username)
	assert.Equal(t, expectedRefreshToken, creds.Password)
	assert.False(t, expiry.IsZero())
}

// ACR's protocol contract requires exchanging the Entra ID access token at /oauth2/exchange
// for an ACR refresh token and using that as the password with the all-zero username.
// Sending the raw Entra token directly as the basic-auth password must fail against the registry's
// token endpoint, while the exchanged refresh token must succeed.
func TestACRExchange_RejectionOfUnexchangedToken(t *testing.T) {
	rawEntraToken := "raw-entra-token-abc"
	exchangedRefreshToken := testJWTWithExpiry(time.Now().Add(time.Hour))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/exchange":
			_ = r.ParseForm()
			if r.PostForm.Get("access_token") == rawEntraToken {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": exchangedRefreshToken})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/oauth2/token":
			user, pass, ok := r.BasicAuth()
			if ok && user == "00000000-0000-0000-0000-000000000000" && pass == exchangedRefreshToken {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "registry-pull-token"})
				return
			}
			w.Header().Set("Www-Authenticate", `Bearer realm="fake",service="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// 1. Verify unexchanged Entra token is rejected by the registry's token endpoint
	reqUnexchanged, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/oauth2/token", nil)
	reqUnexchanged.SetBasicAuth("00000000-0000-0000-0000-000000000000", rawEntraToken)
	resp1, err := server.Client().Do(reqUnexchanged)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp1.StatusCode, "unexchanged Entra access token must be rejected as basic password")

	// 2. Perform the exchange and verify the exchanged refresh token is accepted
	origHTTP := acrHTTPClient
	defer func() { acrHTTPClient = origHTTP }()
	acrHTTPClient = server.Client()

	refreshToken, _, err := exchangeACRRefreshToken(context.Background(), server.URL, rawEntraToken)
	require.NoError(t, err)
	assert.Equal(t, exchangedRefreshToken, refreshToken)

	reqExchanged, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/oauth2/token", nil)
	reqExchanged.SetBasicAuth("00000000-0000-0000-0000-000000000000", refreshToken)
	resp2, err := server.Client().Do(reqExchanged)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "exchanged ACR refresh token must authenticate successfully")
}

func TestACRExchange_RedirectsNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.com/leak", http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	_, _, err := exchangeACRRefreshToken(context.Background(), server.URL, "sensitive-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACR exchange returned HTTP 307")
}

func TestACRExchange_FailurePropagates(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErrMsg string
	}{
		{
			name: "http 401 unauthorized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("invalid access_token"))
			},
			wantErrMsg: "ACR exchange returned HTTP 401",
		},
		{
			name: "http 500 internal server error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("service unavailable"))
			},
			wantErrMsg: "ACR exchange returned HTTP 500",
		},
		{
			name: "malformed json response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{invalid-json"))
			},
			wantErrMsg: "decoding ACR exchange response",
		},
		{
			name: "empty refresh token in response",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"refresh_token": ""})
			},
			wantErrMsg: "empty refresh_token",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			origHTTP := acrHTTPClient
			defer func() { acrHTTPClient = origHTTP }()
			acrHTTPClient = server.Client()

			_, _, err := exchangeACRRefreshToken(context.Background(), server.URL, "dummy-token")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

func TestACRExchange_TokenExpiryBounding(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	t.Run("refresh token expiry earlier than entra expiry", func(t *testing.T) {
		entraExp := now.Add(2 * time.Hour)
		refreshExp := now.Add(30 * time.Minute)

		origTokenFn := ACRTokenFn
		origExchangeFn := ACRExchangeFn
		defer func() {
			ACRTokenFn = origTokenFn
			ACRExchangeFn = origExchangeFn
		}()

		ACRTokenFn = func(_ context.Context, _ string) (string, time.Time, error) {
			return "token", entraExp, nil
		}
		ACRExchangeFn = func(_ context.Context, _, _ string) (string, time.Time, error) {
			return "refresh", refreshExp, nil
		}

		_, expiry, err := acrCredentials(context.Background(), "myreg.azurecr.io")
		require.NoError(t, err)
		assert.Equal(t, refreshExp, expiry)
	})

	t.Run("entra expiry earlier than refresh token expiry", func(t *testing.T) {
		entraExp := now.Add(20 * time.Minute)
		refreshExp := now.Add(2 * time.Hour)

		origTokenFn := ACRTokenFn
		origExchangeFn := ACRExchangeFn
		defer func() {
			ACRTokenFn = origTokenFn
			ACRExchangeFn = origExchangeFn
		}()

		ACRTokenFn = func(_ context.Context, _ string) (string, time.Time, error) {
			return "token", entraExp, nil
		}
		ACRExchangeFn = func(_ context.Context, _, _ string) (string, time.Time, error) {
			return "refresh", refreshExp, nil
		}

		_, expiry, err := acrCredentials(context.Background(), "myreg.azurecr.io")
		require.NoError(t, err)
		assert.Equal(t, entraExp, expiry)
	})
}

// Concurrent scans against the same ACR host must collapse into a single fetch,
// preventing rate limiting on Azure Entra ID and /oauth2/exchange under load.
func TestACRCredentials_ConcurrentMissesCollapseToOneFetch(t *testing.T) {
	orig := ACRCredsFn
	defer func() { ACRCredsFn = orig; ResetCaches() }()
	ResetCaches()

	const n = 20
	var calls, joined int32
	allJoined := make(chan struct{})

	// onMiss barrier guarantees all n callers have reached the miss path before the fetch completes
	acrCache.onMiss = func() {
		if atomic.AddInt32(&joined, 1) == n {
			close(allJoined)
		}
	}

	ACRCredsFn = func(ctx context.Context, host string) (*image.RegistryCredentials, time.Time, error) {
		atomic.AddInt32(&calls, 1)
		<-allJoined
		return &image.RegistryCredentials{Username: "00000000-0000-0000-0000-000000000000", Password: "shared-token"}, time.Now().Add(time.Hour), nil
	}

	var wg sync.WaitGroup
	wg.Add(n)
	results := make([]*image.RegistryCredentials, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			creds, err := ACR{}.Credentials(context.Background(), "concurrent.azurecr.io/app:v1")
			require.NoError(t, err)
			results[idx] = creds
		}(i)
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "concurrent cache misses must collapse into exactly one upstream fetch")
	for i := 0; i < n; i++ {
		assert.Equal(t, "shared-token", results[i].Password)
	}
}

// ACR credentials are cached per registry host: Workload Identity federation can map different
// identities or tenant contexts across separate registries, so one host's cached token
// must never be handed out for another host.
func TestACRCredentialsIsolatesCacheAcrossHosts(t *testing.T) {
	orig := ACRCredsFn
	defer func() { ACRCredsFn = orig; ResetCaches() }()
	ResetCaches()

	var calls int32
	ACRCredsFn = func(_ context.Context, host string) (*image.RegistryCredentials, time.Time, error) {
		n := atomic.AddInt32(&calls, 1)
		return &image.RegistryCredentials{Username: "00000000-0000-0000-0000-000000000000", Password: fmt.Sprintf("%s-%d", host, n)}, time.Now().Add(time.Hour), nil
	}

	hostA := "registrya.azurecr.io/foo/bar:v1"
	hostB := "registryb.azurecr.io/foo/bar:v1"

	credsA, err := ACR{}.Credentials(context.Background(), hostA)
	require.NoError(t, err)
	credsB, err := ACR{}.Credentials(context.Background(), hostB)
	require.NoError(t, err)

	assert.Equal(t, int32(2), calls, "different ACR hosts must each fetch their own credentials")
	assert.NotEqual(t, credsA.Password, credsB.Password)

	// Second fetch should be served from cache
	credsA2, err := ACR{}.Credentials(context.Background(), hostA)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls, "repeat fetch for already-cached host must not refetch")
	assert.Same(t, credsA, credsA2)
}

func TestACRCredentialsFailurePropagates(t *testing.T) {
	orig := ACRCredsFn
	defer func() { ACRCredsFn = orig; ResetCaches() }()
	ResetCaches()

	want := errors.New("ambient Azure credentials unavailable")
	ACRCredsFn = func(context.Context, string) (*image.RegistryCredentials, time.Time, error) { return nil, time.Time{}, want }

	_, err := ACR{}.Credentials(context.Background(), "myreg.azurecr.io/foo/bar")
	assert.ErrorIs(t, err, want)
}
