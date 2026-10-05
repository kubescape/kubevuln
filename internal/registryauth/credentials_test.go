package registryauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentials_authenticatorSelection(t *testing.T) {
	tests := []struct {
		name              string
		cred              domain.RegistryCredentials
		wantAuthenticator bool
	}{
		{
			name:              "identity token alone uses the oauth authenticator",
			cred:              domain.RegistryCredentials{Authority: "myacr.azurecr.io", IdentityToken: "refresh"},
			wantAuthenticator: true,
		},
		{
			name:              "registry token keeps the bearer path",
			cred:              domain.RegistryCredentials{Token: "access", IdentityToken: "refresh"},
			wantAuthenticator: false,
		},
		{
			name:              "basic pair keeps the basic path",
			cred:              domain.RegistryCredentials{Username: "user", Password: "pass", IdentityToken: "refresh"},
			wantAuthenticator: false,
		},
		{
			name:              "no identity token leaves the authenticator unset",
			cred:              domain.RegistryCredentials{Username: "user", Password: "pass"},
			wantAuthenticator: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Credentials([]domain.RegistryCredentials{tt.cred})
			require.Len(t, got, 1)
			assert.Equal(t, tt.cred.Authority, got[0].Authority)
			assert.Equal(t, tt.cred.Username, got[0].Username)
			assert.Equal(t, tt.cred.Password, got[0].Password)
			assert.Equal(t, tt.cred.Token, got[0].Token)
			assert.Equal(t, tt.wantAuthenticator, got[0].Authenticator != nil)
		})
	}
}

// fakeOAuthRegistry is a registry that only accepts an access token obtained by
// exchanging refreshToken at its token endpoint, the way ACR and Artifact Registry do.
type fakeOAuthRegistry struct {
	refreshToken string
	accessToken  string
	exchanges    atomic.Int32
	// bearers records every Authorization header sent to /v2/ endpoints.
	bearers chan string
}

func (f *fakeOAuthRegistry) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// The GET (basic) token flow has no refresh token to offer.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		require.NoError(t, r.ParseForm())
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != f.refreshToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": f.accessToken})
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		select {
		case f.bearers <- auth:
		default:
		}
		if auth != "Bearer "+f.accessToken {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="http://%s/token",service="fake",scope="repository:repo:pull"`, r.Host))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v2/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.Header().Set("Docker-Content-Digest", "sha256:0000000000000000000000000000000000000000000000000000000000000000")
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func headWithCredentials(t *testing.T, serverURL string, creds []domain.RegistryCredentials) error {
	t.Helper()
	u, err := url.Parse(serverURL)
	require.NoError(t, err)
	opts := image.RegistryOptions{InsecureUseHTTP: true, Credentials: Credentials(creds)}
	auth := opts.Authenticator(u.Host)
	if auth == nil {
		auth = authn.Anonymous
	}
	ref, err := name.ParseReference(u.Host+"/repo:latest", name.Insecure)
	require.NoError(t, err)
	_, err = remote.Head(ref, remote.WithAuth(auth))
	return err
}

func TestCredentials_identityTokenIsExchangedForAccessToken(t *testing.T) {
	registry := &fakeOAuthRegistry{refreshToken: "refresh-token", accessToken: "access-token", bearers: make(chan string, 16)}
	server := httptest.NewServer(registry.handler(t))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")

	err := headWithCredentials(t, server.URL, []domain.RegistryCredentials{
		{Authority: host, IdentityToken: registry.refreshToken},
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), registry.exchanges.Load(), "refresh token should be exchanged exactly once")

	close(registry.bearers)
	for auth := range registry.bearers {
		assert.NotContains(t, auth, registry.refreshToken, "refresh token must never be sent as a bearer credential")
	}
}

func TestCredentials_identityTokenAsBearerIsRejected(t *testing.T) {
	// Sending the refresh token directly as a bearer token, which is what copying
	// IdentityToken into Token would do, is rejected and never triggers an exchange.
	registry := &fakeOAuthRegistry{refreshToken: "refresh-token", accessToken: "access-token", bearers: make(chan string, 16)}
	server := httptest.NewServer(registry.handler(t))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")

	err := headWithCredentials(t, server.URL, []domain.RegistryCredentials{
		{Authority: host, Token: registry.refreshToken},
	})
	require.Error(t, err)
	assert.Equal(t, int32(0), registry.exchanges.Load())
}
