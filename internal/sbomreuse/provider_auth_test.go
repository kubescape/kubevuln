package sbomreuse

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/stretchr/testify/require"
)

func TestAcquireRegistryCredentials(t *testing.T) {
	for _, mode := range []string{"explicit host credentials", "keychain credentials", "anonymous after rejected keychain"} {
		t.Run(mode, func(t *testing.T) {
			var enforce atomic.Bool
			var authenticated, rejected, anonymous atomic.Int64
			reg := registry.New(registry.WithReferrersSupport(true))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if enforce.Load() {
					user, password, hasAuth := r.BasicAuth()
					valid := hasAuth && user == "test-user" && password == "test-password"
					if mode == "anonymous after rejected keychain" {
						if r.Header.Get("Authorization") != "" {
							rejected.Add(1)
							w.Header().Set("WWW-Authenticate", `Basic realm="test-registry"`)
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						anonymous.Add(1)
					} else {
						if !valid {
							w.Header().Set("WWW-Authenticate", `Basic realm="test-registry"`)
							w.WriteHeader(http.StatusUnauthorized)
							return
						}
						authenticated.Add(1)
					}
				}
				reg.ServeHTTP(w, r)
			}))
			defer server.Close()
			repo, err := name.NewRepository(strings.TrimPrefix(server.URL, "http://")+"/team/image", name.Insecure)
			require.NoError(t, err)
			ref := publishImage(t, repo, "amd64")
			p, key := testPolicy(t, repo.Name())
			policy, err := CompilePolicy(p)
			require.NoError(t, err)
			client, err := newRegistryClient(context.Background(), repo, image.RegistryOptions{InsecureUseHTTP: true}, policy)
			require.NoError(t, err)
			defer client.budget.base.(*http.Transport).CloseIdleConnections()
			subject, err := client.resolve(ref, "linux/amd64")
			require.NoError(t, err)
			publishEnvelope(t, repo, subject, signStatement(t, subject, inventory(t, subject), key))

			configDir := t.TempDir()
			t.Setenv("DOCKER_CONFIG", configDir)
			auth := base64.StdEncoding.EncodeToString([]byte("test-user:test-password"))
			if mode == "anonymous after rejected keychain" {
				auth = base64.StdEncoding.EncodeToString([]byte("stale-user:stale-password"))
			}
			config, err := json.Marshal(map[string]any{"auths": map[string]any{repo.RegistryStr(): map[string]string{"auth": auth}}})
			require.NoError(t, err)
			if mode == "explicit host credentials" {
				// A matching keychain credential must not hide broken explicit selection.
				config = []byte(`{"auths":{}}`)
			}
			require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.json"), config, 0600))
			opts := domain.RegistryOptions{InsecureUseHTTP: true, Platform: "linux/amd64"}
			if mode == "explicit host credentials" {
				opts.Credentials = []domain.RegistryCredentials{{Authority: repo.RegistryStr(), Username: "test-user", Password: "test-password"}}
			}
			enforce.Store(true)
			sbom, err := NewProvider(policy).Acquire(context.Background(), "test-image", ref.Name(), opts)
			require.NoError(t, err)
			require.True(t, sbom.Imported())
			require.Equal(t, ref.Name(), sbom.Annotations[domain.SBOMImportSubject])
			if mode == "anonymous after rejected keychain" {
				require.Positive(t, rejected.Load(), "the initial attempt must try Docker credentials")
				require.Positive(t, anonymous.Load(), "the retry must read the inventory anonymously")
			} else {
				require.Positive(t, authenticated.Load())
			}
		})
	}
}
