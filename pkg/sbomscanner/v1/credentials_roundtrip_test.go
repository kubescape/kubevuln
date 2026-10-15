package v1

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/syftsource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_IdentityTokenRoundTrip sends an identity token through the client, the
// gRPC request and the sidecar server, and checks that the registry pull uses the access
// token obtained by exchanging it, never the refresh token itself.
func TestIntegration_IdentityTokenRoundTrip(t *testing.T) {
	const refreshToken, accessToken = "refresh-token", "access-token"

	layerBytes, layerHash, diffID, err := makeDummyTarGz(100)
	require.NoError(t, err)
	configBytes := []byte(fmt.Sprintf(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":["sha256:%s"]}}`, diffID))
	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))
	manifest := fmt.Sprintf(`{
		"schemaVersion": 2,
		"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
		"config": {"mediaType": "application/vnd.docker.container.image.v1+json", "size": %d, "digest": "sha256:%s"},
		"layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip", "size": %d, "digest": "sha256:%s"}]
	}`, len(configBytes), configHash, len(layerBytes), layerHash)

	var exchanges atomic.Int32
	var mu sync.Mutex
	var authHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if r.Method != http.MethodPost || r.ParseForm() != nil ||
				r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != refreshToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			exchanges.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
			return
		}

		auth := r.Header.Get("Authorization")
		mu.Lock()
		authHeaders = append(authHeaders, auth)
		mu.Unlock()
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		if auth != "Bearer "+accessToken {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Bearer realm="http://%s/token",service="fake",scope="repository:test-image:pull"`, r.Host))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/":
			w.WriteHeader(http.StatusOK)
		case "/v2/test-image/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			_, _ = w.Write([]byte(manifest))
		case fmt.Sprintf("/v2/test-image/blobs/sha256:%s", configHash):
			_, _ = w.Write(configBytes)
		case fmt.Sprintf("/v2/test-image/blobs/sha256:%s", layerHash):
			_, _ = w.Write(layerBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Stub the cataloger: this test is about the pull, not about what Syft finds in the image.
	cataloger := syftsource.SBOMCatalogerFunc(func(_ context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		return &sbom.SBOM{}, nil
	})
	client, srv, sock := startIntegrationServer(t, WithCataloger(cataloger))
	defer srv.Stop()
	defer os.Remove(sock)
	defer client.Close()

	result, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:  u.Host + "/test-image",
		ImageTag: u.Host + "/test-image:latest",
		Options: domain.RegistryOptions{
			InsecureUseHTTP: true,
			Platform:        "linux/amd64",
			Credentials:     []domain.RegistryCredentials{{Authority: u.Host, IdentityToken: refreshToken}},
		},
		MaxImageSize: 1 << 30,
		MaxSBOMSize:  1 << 20,
		Timeout:      time.Minute,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.ErrorMessage)
	assert.NotNil(t, result.SyftDocument)
	assert.GreaterOrEqual(t, exchanges.Load(), int32(1), "identity token should be exchanged at the token endpoint")

	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, authHeaders, "Bearer "+accessToken)
	for _, auth := range authHeaders {
		assert.False(t, strings.Contains(auth, refreshToken), "refresh token must never be sent as a bearer credential")
	}
}
