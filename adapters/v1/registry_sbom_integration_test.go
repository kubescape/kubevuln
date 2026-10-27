//go:build dockerfixture

package v1

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	oci "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/kubescape/kubevuln/core/domain"
	"github.com/kubescape/kubevuln/internal/sbomreuse"
	"github.com/kubescape/kubevuln/repositories"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/stretchr/testify/require"
)

type inventoryArtifact []byte

func (a inventoryArtifact) RawManifest() ([]byte, error)        { return a, nil }
func (a inventoryArtifact) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

func publishInventory(t *testing.T, ref name.Digest, raw []byte, key ed25519.PrivateKey) {
	t.Helper()
	d, err := remote.Get(ref)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]any{"_type": sbomreuse.StatementType, "subject": []any{map[string]any{"name": ref.Context().Name(), "digest": map[string]string{d.Digest.Algorithm: d.Digest.Hex}}}, "predicateType": sbomreuse.PredicateType, "predicate": json.RawMessage(raw)})
	require.NoError(t, err)
	env, err := json.Marshal(dsse.Envelope{PayloadType: sbomreuse.ArtifactType, Payload: base64.StdEncoding.EncodeToString(payload), Signatures: []dsse.Signature{{Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, dsse.PAE(sbomreuse.ArtifactType, payload)))}}})
	require.NoError(t, err)
	blob := static.NewLayer(env, types.MediaType(sbomreuse.EnvelopeMediaType))
	require.NoError(t, remote.WriteLayer(ref.Context(), blob))
	hash, err := blob.Digest()
	require.NoError(t, err)
	cfg := static.NewLayer([]byte("{}"), types.MediaType(sbomreuse.ArtifactType))
	require.NoError(t, remote.WriteLayer(ref.Context(), cfg))
	cfgHash, err := cfg.Digest()
	require.NoError(t, err)
	m := struct {
		oci.Manifest
		ArtifactType string `json:"artifactType"`
	}{Manifest: oci.Manifest{SchemaVersion: 2, MediaType: types.OCIManifestSchema1, Subject: &d.Descriptor, Config: oci.Descriptor{MediaType: types.MediaType(sbomreuse.ArtifactType), Digest: cfgHash, Size: 2}, Layers: []oci.Descriptor{{MediaType: types.MediaType(sbomreuse.EnvelopeMediaType), Digest: hash, Size: int64(len(env))}}}, ArtifactType: sbomreuse.ArtifactType}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, remote.Put(ref.Context().Tag("sbom"), inventoryArtifact(b)))
}

// The empty-image case runs in ordinary dockerfixture CI. Optional Docker-exported
// Alpine/Nginx tarballs exercise the identical path with real package inventories.
func TestRegistrySBOMRealParity(t *testing.T) {
	g, stop, err := NewGrypeAdapterFixedDB()
	if errors.Is(err, ErrDockerUnavailable) {
		t.Skipf("skipping: grype offline db container unavailable (container runtime not usable): %v", err)
	}
	require.NoError(t, err)
	defer stop()
	ctx := context.WithValue(context.Background(), domain.TimestampKey{}, time.Now().Unix())
	ctx = context.WithValue(ctx, domain.ScanIDKey{}, "sbom-reuse-parity")
	ctx = context.WithValue(ctx, domain.WorkloadKey{}, domain.ScanCommand{})
	require.True(t, g.Ready(ctx))
	fixtures := map[string]string{"empty": ""}
	for _, fixture := range []string{"alpine", "nginx"} {
		if path := os.Getenv("SBOM_REUSE_" + strings.ToUpper(fixture) + "_TAR"); path != "" {
			fixtures[fixture] = path
		}
	}
	for fixture, path := range fixtures {
		t.Run(fixture, func(t *testing.T) {
			img, err := mutate.ConfigFile(empty.Image, &oci.ConfigFile{OS: "linux", Architecture: "arm64"})
			require.NoError(t, err)
			if path != "" {
				img, err = tarball.ImageFromPath(path, nil)
				require.NoError(t, err)
			}
			manifest, err := img.Manifest()
			require.NoError(t, err)
			layerPaths := map[string]bool{}
			for _, layer := range manifest.Layers {
				layerPaths["/v2/image/blobs/"+layer.Digest.String()] = true
			}
			var layerGets atomic.Int64
			handler := registry.New(registry.WithReferrersSupport(true))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && layerPaths[r.URL.Path] {
					layerGets.Add(1)
				}
				handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			repo, err := name.NewRepository(strings.TrimPrefix(server.URL, "http://")+"/image", name.Insecure)
			require.NoError(t, err)
			h, err := img.Digest()
			require.NoError(t, err)
			ref := repo.Digest(h.String())
			require.NoError(t, remote.Write(ref, img))
			cfg, err := img.ConfigFile()
			require.NoError(t, err)
			platform := oci.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
			opts := domain.RegistryOptions{InsecureUseHTTP: true, Platform: platform.String()}
			local := NewSyftAdapter(time.Minute, 512*1024*1024, 20*1024*1024, false, nil)
			layerGets.Store(0)
			normal, err := local.CreateSBOM(ctx, "fixture", ref.Name(), "", opts)
			require.NoError(t, err)
			require.NotNil(t, normal.Content)
			normalGets := layerGets.Load()
			raw, err := json.Marshal(normal.Content)
			require.NoError(t, err)
			var header struct {
				Descriptor struct {
					Version string `json:"version"`
				} `json:"descriptor"`
			}
			require.NoError(t, json.Unmarshal(raw, &header))
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			der, err := x509.MarshalPKIXPublicKey(pub)
			require.NoError(t, err)
			policy, err := sbomreuse.CompilePolicy(sbomreuse.Policy{Repositories: map[string]sbomreuse.Producer{repo.Name(): {PublicKeys: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}, SyftVersion: header.Descriptor.Version, SchemaVersion: "16.0.39"}}})
			require.NoError(t, err)
			provider := sbomreuse.NewProvider(policy)
			// With no attachment yet, the real decorator must invoke Syft normally.
			layerGets.Store(0)
			fallback, err := NewRegistrySBOMAdapter(local, provider).CreateSBOM(ctx, "fixture", ref.Name(), "", opts)
			require.NoError(t, err)
			require.False(t, fallback.Imported())
			require.Equal(t, normal.Content, fallback.Content)
			if path != "" {
				require.Positive(t, layerGets.Load())
			}

			publishInventory(t, ref, raw, key)
			layerGets.Store(0)
			imported, err := provider.Acquire(ctx, "fixture", ref.Name(), opts)
			require.NoError(t, err)
			require.True(t, imported.Imported())
			require.Zero(t, layerGets.Load())
			require.Equal(t, normal.Content, imported.Content)
			a, err := g.ScanSBOM(ctx, normal)
			require.NoError(t, err)
			b, err := g.ScanSBOM(ctx, imported)
			require.NoError(t, err)
			require.Equal(t, a.Content.Matches, b.Content.Matches)
			require.Equal(t, a.Content.IgnoredMatches, b.Content.IgnoredMatches)
			if path != "" {
				require.NotEmpty(t, a.Content.Matches)
				require.Positive(t, normalGets)
			}
			store := repositories.NewFakeAPIServerStorage("kubescape")
			require.NoError(t, store.StoreSBOM(ctx, imported, false))
			cached, err := store.GetSBOM(ctx, "fixture", local.Version())
			require.ErrorIs(t, err, domain.ErrOutdatedSBOM)
			require.True(t, provider.CachedEligible(cached, ref.Name(), opts))
			t.Logf("REAL_PARITY fixture=%s packages=%d matches=%d image_layer_GETs=%d->0 package_records_equal=true match_records_equal=true stored_cache_eligible=true DB=%s", fixture, len(imported.Content.Artifacts), len(b.Content.Matches), normalGets, g.DBVersion(ctx))
		})
	}
}
